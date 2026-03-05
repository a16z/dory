use metal::{Buffer, ComputePipelineState, Device, MTLResourceOptions, MTLSize};
use std::collections::HashMap;
use std::path::Path;

/// Thin wrapper around a Metal device + compiled shader library.
pub struct MetalGpu {
    device: Device,
    library: metal::Library,
    queue: metal::CommandQueue,
    pipelines: HashMap<String, ComputePipelineState>,
}

/// 8 × 32-bit limb representation matching the GPU Fp struct layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FpLimbs {
    /// Little-endian 32-bit limbs of a 256-bit field element in Montgomery form.
    pub limbs: [u32; 8],
}

/// Fp2 element: two Fp limbs (c0 = real, c1 = imaginary).
/// Layout matches the GPU `Fp2` struct.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fp2Limbs {
    /// Real part (c0).
    pub c0: FpLimbs,
    /// Imaginary part, coefficient of u (c1).
    pub c1: FpLimbs,
}

/// Fp6 element: three Fp2 components (c0, c1, c2).
/// Layout matches the GPU `Fp6` struct: Fp6 = Fp2[v]/(v³ − ξ).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fp6Limbs {
    /// Coefficient of 1.
    pub c0: Fp2Limbs,
    /// Coefficient of v.
    pub c1: Fp2Limbs,
    /// Coefficient of v².
    pub c2: Fp2Limbs,
}

/// Fp12 element: two Fp6 components (c0, c1).
/// Layout matches the GPU `Fp12` struct: Fp12 = Fp6[w]/(w² − v).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fp12Limbs {
    /// Coefficient of 1.
    pub c0: Fp6Limbs,
    /// Coefficient of w.
    pub c1: Fp6Limbs,
}

/// Line evaluation coefficient (3 × Fp2), matching the GPU `EllCoeff` struct.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EllCoeffLimbs {
    /// First coefficient.
    pub c0: Fp2Limbs,
    /// Second coefficient.
    pub c1: Fp2Limbs,
    /// Third coefficient.
    pub c2: Fp2Limbs,
}

/// Number of precomputed line coefficients per BN254 pairing.
pub const NUM_ELL_COEFFS: usize = 87;

/// 8 × 32-bit limb representation for Fr (scalar field) matching the GPU Fr struct layout.
/// Same physical layout as FpLimbs but semantically distinct (different modulus).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrLimbs {
    /// Little-endian 32-bit limbs of a 256-bit scalar field element in Montgomery form.
    pub limbs: [u32; 8],
}

/// GLV-2 decomposed scalar for G1 operations.
/// Contains two ~128-bit sub-scalars and negate flags.
/// Layout matches the GPU `GlvScalar2` struct.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GlvScalar2 {
    /// First sub-scalar (raw, non-Montgomery form).
    pub k1: FrLimbs,
    /// Second sub-scalar (raw, non-Montgomery form).
    pub k2: FrLimbs,
    /// 1 if the first base should be negated, 0 otherwise.
    pub negate1: u32,
    /// 1 if the endomorphism base should be negated, 0 otherwise.
    pub negate2: u32,
}

/// G1 affine point matching the GPU `g1_affine` struct layout.
/// Uses explicit infinity flag (is_inf = 1 for point at infinity).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G1AffineLimbs {
    /// x-coordinate (Fp in Montgomery form).
    pub x: FpLimbs,
    /// y-coordinate (Fp in Montgomery form).
    pub y: FpLimbs,
    /// 1 if this is the point at infinity, 0 otherwise.
    pub is_inf: u32,
}

/// G1 Jacobian point matching the GPU `g1_jacobian` struct layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G1JacobianLimbs {
    /// X-coordinate (Fp in Montgomery form).
    pub x: FpLimbs,
    /// Y-coordinate (Fp in Montgomery form).
    pub y: FpLimbs,
    /// Z-coordinate (Fp in Montgomery form).
    pub z: FpLimbs,
}

/// G2 affine point matching the GPU `g2_affine` struct layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G2AffineLimbs {
    /// x-coordinate (Fp2 in Montgomery form).
    pub x: Fp2Limbs,
    /// y-coordinate (Fp2 in Montgomery form).
    pub y: Fp2Limbs,
    /// 1 if this is the point at infinity, 0 otherwise.
    pub is_inf: u32,
}

/// G2 Jacobian point matching the GPU `g2_jacobian` struct layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G2JacobianLimbs {
    /// X-coordinate (Fp2 in Montgomery form).
    pub x: Fp2Limbs,
    /// Y-coordinate (Fp2 in Montgomery form).
    pub y: Fp2Limbs,
    /// Z-coordinate (Fp2 in Montgomery form).
    pub z: Fp2Limbs,
}

/// MSM constant-buffer parameters matching the GPU `MsmParams` struct.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MsmParams {
    /// Number of (scalar, point) pairs.
    pub n: u32,
    /// Window size in bits.
    pub c: u32,
    /// Number of windows: ceil(256 / c).
    pub num_windows: u32,
    /// Number of buckets per window: 2^(c-1) (signed-digit halving).
    pub num_buckets: u32,
}

impl MsmParams {
    /// Compute MSM parameters for `n` points with window size `c`.
    pub fn new(n: u32, c: u32) -> Self {
        let num_windows = (256 + c - 1) / c;
        let num_buckets = 1u32 << (c - 1);
        Self {
            n,
            c,
            num_windows,
            num_buckets,
        }
    }

    /// Heuristic: choose window size based on number of points.
    /// Optimal c ≈ ln(n) / ln(2), clamped to [4, 16].
    pub fn optimal_c(n: u32) -> u32 {
        let log2_n = (32 - n.leading_zeros()).max(1);
        log2_n.clamp(4, 16)
    }
}

/// Pre-allocated GPU buffers for a binary kernel (a, b → result).
/// Keeps data GPU-resident so repeated dispatches avoid allocation overhead.
pub struct BinaryBuffers {
    pub(crate) buf_a: Buffer,
    pub(crate) buf_b: Buffer,
    pub(crate) buf_out: Buffer,
    pub(crate) n: usize,
}

/// Pre-allocated GPU buffers for a 4-buffer vector-op kernel (a, b, out, scalar).
/// Keeps data GPU-resident so repeated dispatches avoid allocation overhead.
pub struct VecOpBuffers {
    pub(crate) buf_a: Buffer,
    pub(crate) buf_b: Buffer,
    pub(crate) buf_out: Buffer,
    pub(crate) buf_scalar: Buffer,
    pub(crate) n: usize,
}

/// Pre-allocated GPU buffers for the Miller loop kernel.
pub struct MillerBuffers {
    pub(crate) buf_g1: Buffer,
    pub(crate) buf_coeffs: Buffer,
    pub(crate) buf_out: Buffer,
    pub(crate) n: usize,
}

impl MetalGpu {
    /// Shader files concatenated in order to form the complete Metal source.
    const SHADER_FILES: &'static [&'static str] =
        &["fp.metal", "ec.metal", "vec_ops.metal", "msm.metal"];

    /// Create a new GPU context, compiling shaders from source.
    ///
    /// Concatenates all shader files in [`SHADER_FILES`] order and compiles
    /// them as a single Metal library. Later files may reference definitions
    /// from earlier files without `#include`.
    pub fn new() -> Self {
        let device = Device::system_default().expect("no Metal GPU found");
        let queue = device.new_command_queue();

        let shader_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/backends/metal/shaders");

        let mut source = String::new();
        for file in Self::SHADER_FILES {
            let path = shader_dir.join(file);
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read shader at {}: {e}", path.display()));
            source.push_str(&content);
            source.push('\n');
        }

        let opts = metal::CompileOptions::new();
        let library = device
            .new_library_with_source(&source, &opts)
            .expect("failed to compile Metal shader");

        Self {
            device,
            library,
            queue,
            pipelines: HashMap::new(),
        }
    }

    /// Get or create a cached compute pipeline for the named kernel.
    pub fn pipeline(&mut self, kernel_name: &str) -> &ComputePipelineState {
        if !self.pipelines.contains_key(kernel_name) {
            let func = self
                .library
                .get_function(kernel_name, None)
                .unwrap_or_else(|_| panic!("kernel '{kernel_name}' not found"));
            let pipeline = self
                .device
                .new_compute_pipeline_state_with_function(&func)
                .expect("failed to create pipeline");
            self.pipelines.insert(kernel_name.to_string(), pipeline);
        }
        &self.pipelines[kernel_name]
    }

    /// Allocate GPU buffers and upload initial data for a binary element-wise kernel.
    /// Works with any `repr(C)` element type (FpLimbs, Fp2Limbs, etc.).
    pub fn alloc_binary<T>(&self, a: &[T], b: &[T]) -> BinaryBuffers {
        assert_eq!(a.len(), b.len());
        let n = a.len();
        let byte_len = (n * std::mem::size_of::<T>()) as u64;

        let buf_a = self.device.new_buffer_with_data(
            a.as_ptr() as *const _,
            byte_len,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_b = self.device.new_buffer_with_data(
            b.as_ptr() as *const _,
            byte_len,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_out = self
            .device
            .new_buffer(byte_len, MTLResourceOptions::StorageModeShared);

        BinaryBuffers {
            buf_a,
            buf_b,
            buf_out,
            n,
        }
    }

    /// Dispatch a binary element-wise kernel on pre-allocated buffers.
    /// Only creates a command buffer + encoder — no allocation, no pipeline lookup.
    pub fn dispatch_binary(&self, pipeline: &ComputePipelineState, bufs: &BinaryBuffers) {
        let cmd = self.queue.new_command_buffer();
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(pipeline);
        enc.set_buffer(0, Some(&bufs.buf_a), 0);
        enc.set_buffer(1, Some(&bufs.buf_b), 0);
        enc.set_buffer(2, Some(&bufs.buf_out), 0);

        let n = bufs.n as u64;
        let threads_per_grid = MTLSize::new(n, 1, 1);
        let max_tg = pipeline.max_total_threads_per_threadgroup();
        let threads_per_group = MTLSize::new(max_tg.min(n), 1, 1);
        enc.dispatch_threads(threads_per_grid, threads_per_group);
        enc.end_encoding();
        cmd.commit();
        cmd.wait_until_completed();
    }

    /// Read results back from a completed binary dispatch.
    /// # Safety
    /// `T` must match the element type the kernel wrote.
    pub fn read_results<T: Copy>(bufs: &BinaryBuffers) -> Vec<T> {
        let ptr = bufs.buf_out.contents() as *const T;
        let mut result = Vec::with_capacity(bufs.n);
        unsafe {
            result.set_len(bufs.n);
            std::ptr::copy_nonoverlapping(ptr, result.as_mut_ptr(), bufs.n);
        }
        result
    }

    /// Convenience: allocate + dispatch + read in one call (for tests).
    pub fn run_binary_kernel<T: Copy>(&mut self, kernel_name: &str, a: &[T], b: &[T]) -> Vec<T> {
        let bufs = self.alloc_binary(a, b);
        let pipeline = self.pipeline(kernel_name).clone();
        self.dispatch_binary(&pipeline, &bufs);
        Self::read_results(&bufs)
    }

    /// Like `run_binary_kernel` but allows different input and output element types.
    ///
    /// The output buffer is sized for `n` elements of type `O`. The kernel must
    /// write exactly `n` elements of `O` to buffer(2).
    pub fn run_binary_kernel_out<I: Copy, O: Copy>(
        &mut self,
        kernel_name: &str,
        a: &[I],
        b: &[I],
    ) -> Vec<O> {
        assert_eq!(a.len(), b.len());
        let n = a.len();
        let in_bytes = (n * std::mem::size_of::<I>()) as u64;
        let out_bytes = (n * std::mem::size_of::<O>()) as u64;

        let buf_a = self.device.new_buffer_with_data(
            a.as_ptr() as *const _,
            in_bytes,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_b = self.device.new_buffer_with_data(
            b.as_ptr() as *const _,
            in_bytes,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_out = self
            .device
            .new_buffer(out_bytes, MTLResourceOptions::StorageModeShared);

        let pipeline = self.pipeline(kernel_name).clone();
        let cmd = self.queue.new_command_buffer();
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(&pipeline);
        enc.set_buffer(0, Some(&buf_a), 0);
        enc.set_buffer(1, Some(&buf_b), 0);
        enc.set_buffer(2, Some(&buf_out), 0);

        let threads_per_grid = MTLSize::new(n as u64, 1, 1);
        let max_tg = pipeline.max_total_threads_per_threadgroup();
        let threads_per_group = MTLSize::new(max_tg.min(n as u64), 1, 1);
        enc.dispatch_threads(threads_per_grid, threads_per_group);
        enc.end_encoding();
        cmd.commit();
        cmd.wait_until_completed();

        let ptr = buf_out.contents() as *const O;
        let mut result = Vec::with_capacity(n);
        unsafe {
            result.set_len(n);
            std::ptr::copy_nonoverlapping(ptr, result.as_mut_ptr(), n);
        }
        result
    }

    /// Allocate GPU buffers for the Miller loop kernel.
    pub fn alloc_miller(&self, g1_xy: &[FpLimbs], coeffs: &[EllCoeffLimbs]) -> MillerBuffers {
        let n = g1_xy.len() / 2;
        assert_eq!(g1_xy.len(), 2 * n);
        assert_eq!(coeffs.len(), n * NUM_ELL_COEFFS);

        let g1_bytes = (g1_xy.len() * std::mem::size_of::<FpLimbs>()) as u64;
        let coeff_bytes = (coeffs.len() * std::mem::size_of::<EllCoeffLimbs>()) as u64;
        let out_bytes = (n * std::mem::size_of::<Fp12Limbs>()) as u64;

        let buf_g1 = self.device.new_buffer_with_data(
            g1_xy.as_ptr() as *const _,
            g1_bytes,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_coeffs = self.device.new_buffer_with_data(
            coeffs.as_ptr() as *const _,
            coeff_bytes,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_out = self
            .device
            .new_buffer(out_bytes, MTLResourceOptions::StorageModeShared);

        MillerBuffers {
            buf_g1,
            buf_coeffs,
            buf_out,
            n,
        }
    }

    /// Dispatch the Miller loop kernel on pre-allocated buffers.
    pub fn dispatch_miller(&self, pipeline: &ComputePipelineState, bufs: &MillerBuffers) {
        let cmd = self.queue.new_command_buffer();
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(pipeline);
        enc.set_buffer(0, Some(&bufs.buf_g1), 0);
        enc.set_buffer(1, Some(&bufs.buf_coeffs), 0);
        enc.set_buffer(2, Some(&bufs.buf_out), 0);

        let n = bufs.n as u64;
        let threads_per_grid = MTLSize::new(n, 1, 1);
        let max_tg = pipeline.max_total_threads_per_threadgroup();
        let threads_per_group = MTLSize::new(max_tg.min(n), 1, 1);
        enc.dispatch_threads(threads_per_grid, threads_per_group);
        enc.end_encoding();
        cmd.commit();
        cmd.wait_until_completed();
    }

    /// Read Miller loop results from completed dispatch.
    pub fn read_miller_results(bufs: &MillerBuffers) -> Vec<Fp12Limbs> {
        let ptr = bufs.buf_out.contents() as *const Fp12Limbs;
        let mut result = Vec::with_capacity(bufs.n);
        unsafe {
            result.set_len(bufs.n);
            std::ptr::copy_nonoverlapping(ptr, result.as_mut_ptr(), bufs.n);
        }
        result
    }

    /// Convenience: allocate + dispatch + read in one call (for tests).
    pub fn run_miller_loop(
        &mut self,
        g1_xy: &[FpLimbs],
        coeffs: &[EllCoeffLimbs],
    ) -> Vec<Fp12Limbs> {
        let bufs = self.alloc_miller(g1_xy, coeffs);
        let pipeline = self.pipeline("miller_loop").clone();
        self.dispatch_miller(&pipeline, &bufs);
        Self::read_miller_results(&bufs)
    }

    // ── Vector operations for Dory reduce-and-fold ──────────────────

    /// Allocate GPU buffers and upload initial data for a vector-op kernel.
    /// Works with any `repr(C)` element type.
    pub fn alloc_vec_op<T, S>(&self, a: &[T], b: &[T], scalar: &S) -> VecOpBuffers {
        assert_eq!(a.len(), b.len());
        let n = a.len();
        let byte_len = (n * std::mem::size_of::<T>()) as u64;

        let buf_a = self.device.new_buffer_with_data(
            a.as_ptr() as *const _,
            byte_len,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_b = self.device.new_buffer_with_data(
            b.as_ptr() as *const _,
            byte_len,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_out = self
            .device
            .new_buffer(byte_len, MTLResourceOptions::StorageModeShared);
        let buf_scalar = self.device.new_buffer_with_data(
            scalar as *const S as *const _,
            std::mem::size_of::<S>() as u64,
            MTLResourceOptions::StorageModeShared,
        );

        VecOpBuffers {
            buf_a,
            buf_b,
            buf_out,
            buf_scalar,
            n,
        }
    }

    /// Dispatch a vector-op kernel on pre-allocated buffers.
    /// Only creates a command buffer + encoder — no allocation, no pipeline lookup.
    pub fn dispatch_vec_op_bufs(&self, pipeline: &ComputePipelineState, bufs: &VecOpBuffers) {
        let cmd = self.queue.new_command_buffer();
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(pipeline);
        enc.set_buffer(0, Some(&bufs.buf_a), 0);
        enc.set_buffer(1, Some(&bufs.buf_b), 0);
        enc.set_buffer(2, Some(&bufs.buf_out), 0);
        enc.set_buffer(3, Some(&bufs.buf_scalar), 0);

        let n64 = bufs.n as u64;
        let threads_per_grid = MTLSize::new(n64, 1, 1);
        let max_tg = pipeline.max_total_threads_per_threadgroup();
        let threads_per_group = MTLSize::new(max_tg.min(n64), 1, 1);
        enc.dispatch_threads(threads_per_grid, threads_per_group);
        enc.end_encoding();
        cmd.commit();
        cmd.wait_until_completed();
    }

    /// Read results back from a completed vector-op dispatch.
    /// # Safety
    /// `T` must match the element type the kernel wrote.
    pub fn read_vec_op_results<T: Copy>(bufs: &VecOpBuffers) -> Vec<T> {
        let ptr = bufs.buf_out.contents() as *const T;
        let mut result = Vec::with_capacity(bufs.n);
        unsafe {
            result.set_len(bufs.n);
            std::ptr::copy_nonoverlapping(ptr, result.as_mut_ptr(), bufs.n);
        }
        result
    }

    /// Allocate a single-element buffer for a broadcast scalar.
    fn alloc_scalar<T>(&self, scalar: &T) -> Buffer {
        let byte_len = std::mem::size_of::<T>() as u64;
        self.device.new_buffer_with_data(
            scalar as *const T as *const _,
            byte_len,
            MTLResourceOptions::StorageModeShared,
        )
    }

    /// Dispatch a 4-buffer vector-op kernel (a, b, out, scalar).
    fn dispatch_vec_op(
        &self,
        pipeline: &ComputePipelineState,
        buf_a: &Buffer,
        buf_b: &Buffer,
        buf_out: &Buffer,
        buf_scalar: &Buffer,
        n: usize,
    ) {
        let cmd = self.queue.new_command_buffer();
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(pipeline);
        enc.set_buffer(0, Some(buf_a), 0);
        enc.set_buffer(1, Some(buf_b), 0);
        enc.set_buffer(2, Some(buf_out), 0);
        enc.set_buffer(3, Some(buf_scalar), 0);

        let n64 = n as u64;
        let threads_per_grid = MTLSize::new(n64, 1, 1);
        let max_tg = pipeline.max_total_threads_per_threadgroup();
        let threads_per_group = MTLSize::new(max_tg.min(n64), 1, 1);
        enc.dispatch_threads(threads_per_grid, threads_per_group);
        enc.end_encoding();
        cmd.commit();
        cmd.wait_until_completed();
    }

    /// Run a G1 vector AXPY: out[i] = vs[i] + scalar * bases[i]
    ///
    /// `scalar_raw` must be in raw (non-Montgomery) form.
    /// Internally decomposes the scalar via GLV-2 for ~2x faster scalar mul.
    pub fn run_g1_scale_bases_add(
        &mut self,
        bases: &[G1JacobianLimbs],
        vs: &[G1JacobianLimbs],
        scalar_raw: &FrLimbs,
    ) -> Vec<G1JacobianLimbs> {
        let glv = super::glv::decompose_scalar_g1(scalar_raw);
        let n = bases.len();
        assert_eq!(n, vs.len());
        let byte_len = (n * std::mem::size_of::<G1JacobianLimbs>()) as u64;

        let buf_a = self.device.new_buffer_with_data(
            bases.as_ptr() as *const _,
            byte_len,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_b = self.device.new_buffer_with_data(
            vs.as_ptr() as *const _,
            byte_len,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_out = self
            .device
            .new_buffer(byte_len, MTLResourceOptions::StorageModeShared);
        let buf_scalar = self.alloc_scalar(&glv);

        let pipeline = self.pipeline("g1_scale_bases_add").clone();
        self.dispatch_vec_op(&pipeline, &buf_a, &buf_b, &buf_out, &buf_scalar, n);

        let ptr = buf_out.contents() as *const G1JacobianLimbs;
        let mut result = Vec::with_capacity(n);
        unsafe {
            result.set_len(n);
            std::ptr::copy_nonoverlapping(ptr, result.as_mut_ptr(), n);
        }
        result
    }

    /// Run a G1 vector fold: out[i] = scalar * vs[i] + addends[i]
    ///
    /// `scalar_raw` must be in raw (non-Montgomery) form.
    /// Internally decomposes the scalar via GLV-2 for ~2x faster scalar mul.
    pub fn run_g1_scale_vs_add(
        &mut self,
        vs: &[G1JacobianLimbs],
        addends: &[G1JacobianLimbs],
        scalar_raw: &FrLimbs,
    ) -> Vec<G1JacobianLimbs> {
        let glv = super::glv::decompose_scalar_g1(scalar_raw);
        let n = vs.len();
        assert_eq!(n, addends.len());
        let byte_len = (n * std::mem::size_of::<G1JacobianLimbs>()) as u64;

        let buf_a = self.device.new_buffer_with_data(
            vs.as_ptr() as *const _,
            byte_len,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_b = self.device.new_buffer_with_data(
            addends.as_ptr() as *const _,
            byte_len,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_out = self
            .device
            .new_buffer(byte_len, MTLResourceOptions::StorageModeShared);
        let buf_scalar = self.alloc_scalar(&glv);

        let pipeline = self.pipeline("g1_scale_vs_add").clone();
        self.dispatch_vec_op(&pipeline, &buf_a, &buf_b, &buf_out, &buf_scalar, n);

        let ptr = buf_out.contents() as *const G1JacobianLimbs;
        let mut result = Vec::with_capacity(n);
        unsafe {
            result.set_len(n);
            std::ptr::copy_nonoverlapping(ptr, result.as_mut_ptr(), n);
        }
        result
    }

    /// Run a G2 vector AXPY: out[i] = vs[i] + scalar * bases[i]
    ///
    /// `scalar_raw` must be in raw (non-Montgomery) form.
    pub fn run_g2_scale_bases_add(
        &mut self,
        bases: &[G2JacobianLimbs],
        vs: &[G2JacobianLimbs],
        scalar_raw: &FrLimbs,
    ) -> Vec<G2JacobianLimbs> {
        let n = bases.len();
        assert_eq!(n, vs.len());
        let byte_len = (n * std::mem::size_of::<G2JacobianLimbs>()) as u64;

        let buf_a = self.device.new_buffer_with_data(
            bases.as_ptr() as *const _,
            byte_len,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_b = self.device.new_buffer_with_data(
            vs.as_ptr() as *const _,
            byte_len,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_out = self
            .device
            .new_buffer(byte_len, MTLResourceOptions::StorageModeShared);
        let buf_scalar = self.alloc_scalar(scalar_raw);

        let pipeline = self.pipeline("g2_scale_bases_add").clone();
        self.dispatch_vec_op(&pipeline, &buf_a, &buf_b, &buf_out, &buf_scalar, n);

        let ptr = buf_out.contents() as *const G2JacobianLimbs;
        let mut result = Vec::with_capacity(n);
        unsafe {
            result.set_len(n);
            std::ptr::copy_nonoverlapping(ptr, result.as_mut_ptr(), n);
        }
        result
    }

    /// Run a G2 vector fold: out[i] = scalar * vs[i] + addends[i]
    ///
    /// `scalar_raw` must be in raw (non-Montgomery) form.
    pub fn run_g2_scale_vs_add(
        &mut self,
        vs: &[G2JacobianLimbs],
        addends: &[G2JacobianLimbs],
        scalar_raw: &FrLimbs,
    ) -> Vec<G2JacobianLimbs> {
        let n = vs.len();
        assert_eq!(n, addends.len());
        let byte_len = (n * std::mem::size_of::<G2JacobianLimbs>()) as u64;

        let buf_a = self.device.new_buffer_with_data(
            vs.as_ptr() as *const _,
            byte_len,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_b = self.device.new_buffer_with_data(
            addends.as_ptr() as *const _,
            byte_len,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_out = self
            .device
            .new_buffer(byte_len, MTLResourceOptions::StorageModeShared);
        let buf_scalar = self.alloc_scalar(scalar_raw);

        let pipeline = self.pipeline("g2_scale_vs_add").clone();
        self.dispatch_vec_op(&pipeline, &buf_a, &buf_b, &buf_out, &buf_scalar, n);

        let ptr = buf_out.contents() as *const G2JacobianLimbs;
        let mut result = Vec::with_capacity(n);
        unsafe {
            result.set_len(n);
            std::ptr::copy_nonoverlapping(ptr, result.as_mut_ptr(), n);
        }
        result
    }

    /// Run Fr field AXPY: out[i] = scalar * left[i] + right[i]
    ///
    /// `scalar_mont` must be in Montgomery form.
    pub fn run_fr_axpy(
        &mut self,
        left: &[FrLimbs],
        right: &[FrLimbs],
        scalar_mont: &FrLimbs,
    ) -> Vec<FrLimbs> {
        let n = left.len();
        assert_eq!(n, right.len());
        let byte_len = (n * std::mem::size_of::<FrLimbs>()) as u64;

        let buf_a = self.device.new_buffer_with_data(
            left.as_ptr() as *const _,
            byte_len,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_b = self.device.new_buffer_with_data(
            right.as_ptr() as *const _,
            byte_len,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_out = self
            .device
            .new_buffer(byte_len, MTLResourceOptions::StorageModeShared);
        let buf_scalar = self.alloc_scalar(scalar_mont);

        let pipeline = self.pipeline("fr_axpy").clone();
        self.dispatch_vec_op(&pipeline, &buf_a, &buf_b, &buf_out, &buf_scalar, n);

        let ptr = buf_out.contents() as *const FrLimbs;
        let mut result = Vec::with_capacity(n);
        unsafe {
            result.set_len(n);
            std::ptr::copy_nonoverlapping(ptr, result.as_mut_ptr(), n);
        }
        result
    }

    // ── G1 Multi-Scalar Multiplication (Pippenger) ──────────────────

    /// Dispatch a single compute kernel with the given buffers and thread count.
    fn dispatch_kernel(
        &self,
        pipeline: &ComputePipelineState,
        buffers: &[&Buffer],
        num_threads: u64,
    ) {
        let cmd = self.queue.new_command_buffer();
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(pipeline);
        for (i, buf) in buffers.iter().enumerate() {
            enc.set_buffer(i as u64, Some(buf), 0);
        }
        let threads_per_grid = MTLSize::new(num_threads, 1, 1);
        let max_tg = pipeline.max_total_threads_per_threadgroup();
        let threads_per_group = MTLSize::new(max_tg.min(num_threads), 1, 1);
        enc.dispatch_threads(threads_per_grid, threads_per_group);
        enc.end_encoding();
        cmd.commit();
        cmd.wait_until_completed();
    }

    /// Create a zero-filled buffer of `byte_len` bytes.
    fn alloc_zeroed(&self, byte_len: u64) -> Buffer {
        let buf = self
            .device
            .new_buffer(byte_len, MTLResourceOptions::StorageModeShared);
        unsafe {
            std::ptr::write_bytes(buf.contents() as *mut u8, 0, byte_len as usize);
        }
        buf
    }

    /// Run G1 MSM: compute Σ scalars[i] * points[i].
    ///
    /// `points` are affine G1 points (in Montgomery form).
    /// `scalars` are 256-bit scalars in **raw** (non-Montgomery) form,
    /// represented as `[u32; 8]` little-endian limbs.
    ///
    /// Uses the heuristic-optimal window size.
    pub fn run_g1_msm(
        &mut self,
        points: &[G1AffineLimbs],
        scalars: &[[u32; 8]],
    ) -> G1JacobianLimbs {
        let c = MsmParams::optimal_c(points.len() as u32);
        self.run_g1_msm_with_c(points, scalars, c)
    }

    /// Run G1 MSM with an explicit window size `c`.
    pub fn run_g1_msm_with_c(
        &mut self,
        points: &[G1AffineLimbs],
        scalars: &[[u32; 8]],
        c: u32,
    ) -> G1JacobianLimbs {
        let bufs = self.alloc_msm(points, scalars, c);
        self.dispatch_msm(&bufs);
        Self::read_msm_result(&bufs)
    }

    /// Pre-allocate all GPU buffers for an MSM dispatch.
    pub fn alloc_msm(&self, points: &[G1AffineLimbs], scalars: &[[u32; 8]], c: u32) -> MsmBuffers {
        let n = points.len();
        assert_eq!(n, scalars.len());
        assert!(n > 0);

        let params = MsmParams::new(n as u32, c);
        let wb_count = (params.num_windows as u64) * (params.num_buckets as u64);

        let buf_scalars = self.device.new_buffer_with_data(
            scalars.as_ptr() as *const _,
            (n * 32) as u64,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_points = self.device.new_buffer_with_data(
            points.as_ptr() as *const _,
            (n * std::mem::size_of::<G1AffineLimbs>()) as u64,
            MTLResourceOptions::StorageModeShared,
        );
        let buf_params = self.device.new_buffer_with_data(
            &params as *const MsmParams as *const _,
            std::mem::size_of::<MsmParams>() as u64,
            MTLResourceOptions::StorageModeShared,
        );

        let digits_bytes = (n as u64) * (params.num_windows as u64) * 4;
        let buf_digits = self
            .device
            .new_buffer(digits_bytes, MTLResourceOptions::StorageModeShared);

        let histogram_bytes = wb_count * 4;
        let buf_histogram = self.alloc_zeroed(histogram_bytes);
        let buf_prefix = self
            .device
            .new_buffer(histogram_bytes, MTLResourceOptions::StorageModeShared);
        let buf_scatter_offsets = self.alloc_zeroed(histogram_bytes);

        let sorted_bytes = (params.num_windows as u64) * (n as u64) * 4;
        let buf_sorted = self
            .device
            .new_buffer(sorted_bytes, MTLResourceOptions::StorageModeShared);

        let bucket_bytes = wb_count * (std::mem::size_of::<G1JacobianLimbs>() as u64);
        let buf_buckets = self
            .device
            .new_buffer(bucket_bytes, MTLResourceOptions::StorageModeShared);

        let window_bytes =
            (params.num_windows as u64) * (std::mem::size_of::<G1JacobianLimbs>() as u64);
        let buf_windows = self
            .device
            .new_buffer(window_bytes, MTLResourceOptions::StorageModeShared);

        let buf_result = self.device.new_buffer(
            std::mem::size_of::<G1JacobianLimbs>() as u64,
            MTLResourceOptions::StorageModeShared,
        );

        MsmBuffers {
            buf_scalars,
            buf_points,
            buf_params,
            buf_digits,
            buf_histogram,
            buf_prefix,
            buf_scatter_offsets,
            buf_sorted,
            buf_buckets,
            buf_windows,
            buf_result,
            params,
        }
    }

    /// Encode one kernel dispatch into an existing command buffer.
    ///
    /// Uses a fresh compute encoder per dispatch; encoder boundaries
    /// provide implicit memory barriers between kernels.
    fn encode_kernel(
        cmd: &metal::CommandBufferRef,
        pipeline: &ComputePipelineState,
        buffers: &[&Buffer],
        num_threads: u64,
    ) {
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(pipeline);
        for (i, buf) in buffers.iter().enumerate() {
            enc.set_buffer(i as u64, Some(buf), 0);
        }
        let threads_per_grid = MTLSize::new(num_threads, 1, 1);
        let max_tg = pipeline.max_total_threads_per_threadgroup();
        let threads_per_group = MTLSize::new(max_tg.min(num_threads), 1, 1);
        enc.dispatch_threads(threads_per_grid, threads_per_group);
        enc.end_encoding();
    }

    /// Dispatch the 7-kernel MSM pipeline on pre-allocated buffers.
    ///
    /// All kernels are encoded into a single command buffer (1 GPU
    /// submission instead of 7). Encoder boundaries provide implicit
    /// memory barriers. Histogram and scatter_offsets are re-zeroed
    /// before dispatch so buffers can be reused across iterations.
    pub fn dispatch_msm(&mut self, bufs: &MsmBuffers) {
        let n = bufs.params.n as u64;
        let wb_count = (bufs.params.num_windows as u64) * (bufs.params.num_buckets as u64);
        let histogram_bytes = wb_count * 4;

        // Re-zero atomic buffers for reuse
        unsafe {
            std::ptr::write_bytes(
                bufs.buf_histogram.contents() as *mut u8,
                0,
                histogram_bytes as usize,
            );
            std::ptr::write_bytes(
                bufs.buf_scatter_offsets.contents() as *mut u8,
                0,
                histogram_bytes as usize,
            );
        }

        // Cache all pipeline states before encoding
        let p1 = self.pipeline("g1_msm_decompose").clone();
        let p2 = self.pipeline("g1_msm_histogram").clone();
        let p3 = self.pipeline("g1_msm_prefix_sum").clone();
        let p4 = self.pipeline("g1_msm_scatter").clone();
        let p5 = self.pipeline("g1_msm_accumulate").clone();
        let p6 = self.pipeline("g1_msm_reduce").clone();
        let p7 = self.pipeline("g1_msm_finalize").clone();

        let cmd = self.queue.new_command_buffer();

        Self::encode_kernel(
            cmd,
            &p1,
            &[&bufs.buf_scalars, &bufs.buf_digits, &bufs.buf_params],
            n,
        );
        Self::encode_kernel(
            cmd,
            &p2,
            &[&bufs.buf_digits, &bufs.buf_histogram, &bufs.buf_params],
            n,
        );
        Self::encode_kernel(
            cmd,
            &p3,
            &[&bufs.buf_histogram, &bufs.buf_prefix, &bufs.buf_params],
            bufs.params.num_windows as u64,
        );
        Self::encode_kernel(
            cmd,
            &p4,
            &[
                &bufs.buf_digits,
                &bufs.buf_prefix,
                &bufs.buf_scatter_offsets,
                &bufs.buf_sorted,
                &bufs.buf_params,
            ],
            n,
        );
        Self::encode_kernel(
            cmd,
            &p5,
            &[
                &bufs.buf_points,
                &bufs.buf_sorted,
                &bufs.buf_prefix,
                &bufs.buf_histogram,
                &bufs.buf_buckets,
                &bufs.buf_params,
            ],
            wb_count,
        );
        Self::encode_kernel(
            cmd,
            &p6,
            &[&bufs.buf_buckets, &bufs.buf_windows, &bufs.buf_params],
            bufs.params.num_windows as u64,
        );
        Self::encode_kernel(
            cmd,
            &p7,
            &[&bufs.buf_windows, &bufs.buf_result, &bufs.buf_params],
            1,
        );

        cmd.commit();
        cmd.wait_until_completed();
    }

    /// Read the MSM result from a completed dispatch.
    pub fn read_msm_result(bufs: &MsmBuffers) -> G1JacobianLimbs {
        let ptr = bufs.buf_result.contents() as *const G1JacobianLimbs;
        unsafe { std::ptr::read(ptr) }
    }
}

// ── High-level arkworks-compatible pairing API ──────────────────────

#[cfg(feature = "arkworks")]
mod ark_conv {
    use super::*;
    use ark_bn254::{Fq as ArkFq, Fq2 as ArkFq2};

    /// Convert an arkworks Fq element to 8×32-bit LE Montgomery limbs.
    pub(crate) fn fq_to_limbs(f: &ArkFq) -> FpLimbs {
        let limbs64: [u64; 4] = unsafe { std::mem::transmute(*f) };
        let mut limbs = [0u32; 8];
        for (i, &w) in limbs64.iter().enumerate() {
            limbs[2 * i] = w as u32;
            limbs[2 * i + 1] = (w >> 32) as u32;
        }
        FpLimbs { limbs }
    }

    /// Convert 8×32-bit LE Montgomery limbs back to an arkworks Fq.
    pub(crate) fn limbs_to_fq(l: &FpLimbs) -> ArkFq {
        let mut limbs64 = [0u64; 4];
        for (i, w) in limbs64.iter_mut().enumerate() {
            *w = l.limbs[2 * i] as u64 | ((l.limbs[2 * i + 1] as u64) << 32);
        }
        unsafe { std::mem::transmute::<[u64; 4], ArkFq>(limbs64) }
    }

    pub(crate) fn fq2_to_limbs(f: &ArkFq2) -> Fp2Limbs {
        Fp2Limbs {
            c0: fq_to_limbs(&f.c0),
            c1: fq_to_limbs(&f.c1),
        }
    }

    pub(crate) fn limbs_to_fq2(l: &Fp2Limbs) -> ArkFq2 {
        ArkFq2::new(limbs_to_fq(&l.c0), limbs_to_fq(&l.c1))
    }

    pub(crate) fn limbs_to_fq6(l: &Fp6Limbs) -> ark_bn254::Fq6 {
        ark_bn254::Fq6::new(
            limbs_to_fq2(&l.c0),
            limbs_to_fq2(&l.c1),
            limbs_to_fq2(&l.c2),
        )
    }

    pub(crate) fn limbs_to_fq12(l: &Fp12Limbs) -> ark_bn254::Fq12 {
        ark_bn254::Fq12::new(limbs_to_fq6(&l.c0), limbs_to_fq6(&l.c1))
    }

    /// Convert arkworks G2Prepared ell_coeffs into GPU-format coefficients.
    pub(crate) fn prepared_to_ell_coeffs(
        g2_prep: &<ark_bn254::Bn254 as ark_ec::pairing::Pairing>::G2Prepared,
    ) -> Vec<EllCoeffLimbs> {
        g2_prep
            .ell_coeffs
            .iter()
            .map(|(c0, c1, c2)| EllCoeffLimbs {
                c0: fq2_to_limbs(c0),
                c1: fq2_to_limbs(c1),
                c2: fq2_to_limbs(c2),
            })
            .collect()
    }
}

#[cfg(feature = "arkworks")]
impl MetalGpu {
    /// Run n parallel Miller loops on GPU, reduce on CPU, return `MillerLoopOutput<Bn254>`.
    ///
    /// Automatically falls back to the CPU arkworks path when `n` is below
    /// [`config::min_gpu_pairs()`](super::config::min_gpu_pairs). Override
    /// the threshold with [`config::set_min_gpu_pairs`](super::config::set_min_gpu_pairs).
    pub fn multi_miller_loop(
        &mut self,
        g1s: &[ark_bn254::G1Affine],
        g2s: &[ark_bn254::G2Affine],
    ) -> ark_ec::pairing::MillerLoopOutput<ark_bn254::Bn254> {
        use ark_bn254::Bn254;
        use ark_ec::pairing::Pairing;

        assert_eq!(g1s.len(), g2s.len());
        let n = g1s.len();
        assert!(n > 0);

        if n < super::config::min_gpu_pairs() {
            let ps: Vec<<Bn254 as Pairing>::G1Prepared> =
                g1s.iter().copied().map(Into::into).collect();
            let qs: Vec<<Bn254 as Pairing>::G2Prepared> =
                g2s.iter().copied().map(Into::into).collect();
            return Bn254::multi_miller_loop(ps, qs);
        }

        self.multi_miller_loop_gpu(g1s, g2s)
    }

    /// Run n parallel Miller loops on GPU, reduce on CPU, then apply final exponentiation.
    ///
    /// Returns the final pairing result (GT element). Automatically dispatches
    /// to CPU or GPU based on [`config::min_gpu_pairs()`](super::config::min_gpu_pairs).
    pub fn multi_pair(
        &mut self,
        g1s: &[ark_bn254::G1Affine],
        g2s: &[ark_bn254::G2Affine],
    ) -> ark_ec::pairing::PairingOutput<ark_bn254::Bn254> {
        use ark_bn254::Bn254;
        use ark_ec::pairing::Pairing;

        let miller_output = self.multi_miller_loop(g1s, g2s);
        Bn254::final_exponentiation(miller_output).expect("Final exponentiation should not fail")
    }

    /// Like [`multi_miller_loop`](Self::multi_miller_loop) but accepts pre-prepared G2 points.
    ///
    /// Use this to avoid re-computing G2 preparation when the same G2 points
    /// are paired repeatedly (e.g. with cached setup parameters).
    /// Respects the same GPU dispatch threshold as `multi_miller_loop`.
    pub fn multi_miller_loop_prepared(
        &mut self,
        g1s: &[ark_bn254::G1Affine],
        g2_preps: &[<ark_bn254::Bn254 as ark_ec::pairing::Pairing>::G2Prepared],
    ) -> ark_ec::pairing::MillerLoopOutput<ark_bn254::Bn254> {
        use ark_bn254::Bn254;
        use ark_ec::pairing::Pairing;

        assert_eq!(g1s.len(), g2_preps.len());
        let n = g1s.len();
        assert!(n > 0);

        if n < super::config::min_gpu_pairs() {
            let ps: Vec<<Bn254 as Pairing>::G1Prepared> =
                g1s.iter().copied().map(Into::into).collect();
            return Bn254::multi_miller_loop(ps, g2_preps.to_vec());
        }

        self.multi_miller_loop_prepared_gpu(g1s, g2_preps)
    }

    /// GPU-only path for multi_miller_loop (no threshold check).
    fn multi_miller_loop_gpu(
        &mut self,
        g1s: &[ark_bn254::G1Affine],
        g2s: &[ark_bn254::G2Affine],
    ) -> ark_ec::pairing::MillerLoopOutput<ark_bn254::Bn254> {
        use ark_bn254::Bn254;
        use ark_ec::pairing::Pairing;

        let g2_preps: Vec<<Bn254 as Pairing>::G2Prepared> =
            g2s.iter().map(|q| (*q).into()).collect();

        self.multi_miller_loop_prepared_gpu(g1s, &g2_preps)
    }

    /// GPU-only path for multi_miller_loop_prepared (no threshold check).
    fn multi_miller_loop_prepared_gpu(
        &mut self,
        g1s: &[ark_bn254::G1Affine],
        g2_preps: &[<ark_bn254::Bn254 as ark_ec::pairing::Pairing>::G2Prepared],
    ) -> ark_ec::pairing::MillerLoopOutput<ark_bn254::Bn254> {
        let n = g1s.len();

        let mut g1_xy = Vec::with_capacity(2 * n);
        let mut all_coeffs = Vec::with_capacity(n * NUM_ELL_COEFFS);
        for i in 0..n {
            g1_xy.push(ark_conv::fq_to_limbs(&g1s[i].x));
            g1_xy.push(ark_conv::fq_to_limbs(&g1s[i].y));
            all_coeffs.extend_from_slice(&ark_conv::prepared_to_ell_coeffs(&g2_preps[i]));
        }

        let bufs = self.alloc_miller(&g1_xy, &all_coeffs);
        let pipeline = self.pipeline("miller_loop").clone();
        self.dispatch_miller(&pipeline, &bufs);
        let results = Self::read_miller_results(&bufs);

        let mut acc = ark_conv::limbs_to_fq12(&results[0]);
        for r in &results[1..] {
            acc *= ark_conv::limbs_to_fq12(r);
        }

        ark_ec::pairing::MillerLoopOutput(acc)
    }
}

/// Pre-allocated GPU buffers for the full MSM pipeline.
pub struct MsmBuffers {
    pub(crate) buf_scalars: Buffer,
    pub(crate) buf_points: Buffer,
    pub(crate) buf_params: Buffer,
    pub(crate) buf_digits: Buffer,
    pub(crate) buf_histogram: Buffer,
    pub(crate) buf_prefix: Buffer,
    pub(crate) buf_scatter_offsets: Buffer,
    pub(crate) buf_sorted: Buffer,
    pub(crate) buf_buckets: Buffer,
    pub(crate) buf_windows: Buffer,
    pub(crate) buf_result: Buffer,
    pub(crate) params: MsmParams,
}
