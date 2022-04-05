// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <tee/entry_fast.h>
#include <optee_msg.h>
#include <sm/optee_smc.h>
#include <kernel/boot.h>
#include <kernel/tee_l2cc_mutex.h>
#include <kernel/virtualization.h>
#include <kernel/misc.h>
#include <mm/core_mmu.h>

#ifdef CFG_TZC400
#include <drivers/tzc400.h>
#endif

#ifdef CFG_CORE_RESERVED_SHM
static void tee_entry_get_shm_config(struct thread_smc_args *args)
{
	args->a0 = OPTEE_SMC_RETURN_OK;
	args->a1 = default_nsec_shm_paddr;
	args->a2 = default_nsec_shm_size;
	/* Should this be TEESMC cache attributes instead? */
	args->a3 = core_mmu_is_shm_cached();
}
#endif

static void tee_entry_fastcall_l2cc_mutex(struct thread_smc_args *args)
{
	TEE_Result ret;
#ifdef ARM32
	paddr_t pa = 0;

	switch (args->a1) {
	case OPTEE_SMC_L2CC_MUTEX_GET_ADDR:
		ret = tee_get_l2cc_mutex(&pa);
		reg_pair_from_64(pa, &args->a2, &args->a3);
		break;
	case OPTEE_SMC_L2CC_MUTEX_SET_ADDR:
		pa = reg_pair_to_64(args->a2, args->a3);
		ret = tee_set_l2cc_mutex(&pa);
		break;
	case OPTEE_SMC_L2CC_MUTEX_ENABLE:
		ret = tee_enable_l2cc_mutex();
		break;
	case OPTEE_SMC_L2CC_MUTEX_DISABLE:
		ret = tee_disable_l2cc_mutex();
		break;
	default:
		args->a0 = OPTEE_SMC_RETURN_EBADCMD;
		return;
	}
#else
	ret = TEE_ERROR_NOT_SUPPORTED;
#endif
	if (ret == TEE_ERROR_NOT_SUPPORTED)
		args->a0 = OPTEE_SMC_RETURN_UNKNOWN_FUNCTION;
	else if (ret)
		args->a0 = OPTEE_SMC_RETURN_EBADADDR;
	else
		args->a0 = OPTEE_SMC_RETURN_OK;
}

static void tee_entry_exchange_capabilities(struct thread_smc_args *args)
{
	bool dyn_shm_en __maybe_unused = false;

	/*
	 * Currently we ignore OPTEE_SMC_NSEC_CAP_UNIPROCESSOR.
	 *
	 * The memory mapping of shared memory is defined as normal
	 * shared memory for SMP systems and normal memory for UP
	 * systems. Currently we map all memory as shared in secure
	 * world.
	 *
	 * When translation tables are created with shared bit cleared for
	 * uniprocessor systems we'll need to check
	 * OPTEE_SMC_NSEC_CAP_UNIPROCESSOR.
	 */

	if (args->a1 & ~OPTEE_SMC_NSEC_CAP_UNIPROCESSOR) {
		/* Unknown capability. */
		args->a0 = OPTEE_SMC_RETURN_ENOTAVAIL;
		return;
	}

	args->a0 = OPTEE_SMC_RETURN_OK;
	args->a1 = 0;
#ifdef CFG_CORE_RESERVED_SHM
	args->a1 |= OPTEE_SMC_SEC_CAP_HAVE_RESERVED_SHM;
#endif
#ifdef CFG_VIRTUALIZATION
	args->a1 |= OPTEE_SMC_SEC_CAP_VIRTUALIZATION;
#endif
	args->a1 |= OPTEE_SMC_SEC_CAP_MEMREF_NULL;

#if defined(CFG_CORE_DYN_SHM)
	dyn_shm_en = core_mmu_nsec_ddr_is_defined();
	if (dyn_shm_en)
		args->a1 |= OPTEE_SMC_SEC_CAP_DYNAMIC_SHM;
#endif

	DMSG("Dynamic shared memory is %sabled", dyn_shm_en ? "en" : "dis");
}

static void tee_entry_disable_shm_cache(struct thread_smc_args *args)
{
	uint64_t cookie;

	if (!thread_disable_prealloc_rpc_cache(&cookie)) {
		args->a0 = OPTEE_SMC_RETURN_EBUSY;
		return;
	}

	if (!cookie) {
		args->a0 = OPTEE_SMC_RETURN_ENOTAVAIL;
		return;
	}

	args->a0 = OPTEE_SMC_RETURN_OK;
	args->a1 = cookie >> 32;
	args->a2 = cookie;
}

static void tee_entry_enable_shm_cache(struct thread_smc_args *args)
{
	if (thread_enable_prealloc_rpc_cache())
		args->a0 = OPTEE_SMC_RETURN_OK;
	else
		args->a0 = OPTEE_SMC_RETURN_EBUSY;
}

static void tee_entry_boot_secondary(struct thread_smc_args *args)
{
#if defined(CFG_BOOT_SECONDARY_REQUEST)
	if (!boot_core_release(args->a1, (paddr_t)(args->a3)))
		args->a0 = OPTEE_SMC_RETURN_OK;
	else
		args->a0 = OPTEE_SMC_RETURN_EBADCMD;
#else
	args->a0 = OPTEE_SMC_RETURN_ENOTAVAIL;
#endif
}

static void tee_entry_get_thread_count(struct thread_smc_args *args)
{
	args->a0 = OPTEE_SMC_RETURN_OK;
	args->a1 = CFG_NUM_THREADS;
}

#if defined(CFG_VIRTUALIZATION)
static void tee_entry_vm_created(struct thread_smc_args *args)
{
	uint16_t guest_id = args->a1;

	/* Only hypervisor can issue this request */
	if (args->a7 != HYP_CLNT_ID) {
		args->a0 = OPTEE_SMC_RETURN_ENOTAVAIL;
		return;
	}

	args->a0 = virt_guest_created(guest_id);
}

static void tee_entry_vm_destroyed(struct thread_smc_args *args)
{
	uint16_t guest_id = args->a1;

	/* Only hypervisor can issue this request */
	if (args->a7 != HYP_CLNT_ID) {
		args->a0 = OPTEE_SMC_RETURN_ENOTAVAIL;
		return;
	}

	args->a0 = virt_guest_destroyed(guest_id);
}
#endif

static void tee_entry_gpu_map_memory (struct thread_smc_args *args)
{
	TEE_Result ret;
	ret = 0;
	ret = core_mmu_map_contiguous_pages((vaddr_t)(args->a1), (paddr_t)(args->a1), 1, MEM_AREA_DDR_OVERALL);
	args->a0 = ret;
}

static void tee_entry_gpu_get_tzasc_region (struct thread_smc_args *args)
{
	TEE_Result ret = 0xFFFFFFFF;
#ifdef CFG_TZC400
	uint8_t i;
	struct tzc_region_config cfg;
	TEE_Result err;
	for (i = 1; i < 9; i++)
	{
		err = tzc_get_region_config (i, &cfg);
		if (err == TEE_SUCCESS)
		{
			if (cfg.base <= args->a1 && cfg.top > args->a1)
			{
				args->a0 = i;
				return 0;
			}
		}
	}
	ret = TEE_ERROR_CORRUPT_OBJECT;
#endif
	args->a0 = ret;
}

static void tee_entry_gpu_set_tzasc_region (struct thread_smc_args *args)
{
	TEE_Result ret = 0xFFFFFFFF;
#ifdef CFG_TZC400
	uint8_t i;
	struct tzc_region_config cfg;
	TEE_Result err;
	uint64_t base = args->a1;
	uint64_t top = args->a1 + args->a2;
	for (i = 1; i < 9; i++)
	{
		err = tzc_get_region_config (i, &cfg);
		if (err == TEE_SUCCESS)
		{
			if (base < cfg.top && top <= cfg.base)
				return TEE_ERROR_STORAGE_NOT_AVAILABLE;
		}
	}
	cfg.filters = 0;
	cfg.base = base;
	cfg.top = top;
	cfg.sec_attr = TZC_REGION_S_RDWR;
	cfg.ns_device_access = 0;

	tzc_configure_region ((uint8_t) args->a3, &cfg);

	ret = TEE_SUCCESS;
#endif
	args->a0 = ret;
}

static void tee_entry_rkp_set_ttbr0_el1 (struct thread_smc_args *args)
{
	__asm volatile (
		"mmid %[mm], %[mm]\n\t"
		"bfi %[ttbr0_el1], %[mm], #48, #16\n\t"
		"msr ttbr0_el1, %[ttbr0_el1]\n\t"
		"isb\n\t"
		: // empty output operand
		: [mm] "r" (args->a1), [ttbr0_el1] "r" (args->a4)
	);
	args->a0 = TEE_SUCCESS;
}

static void tee_entry_rkp_erratum_qcom_falkor_1003 (struct thread_smc_args *args)
{
	__asm volatile (
		"mrs x3, #1\n\t"
		"bfi x2, x3, #48, #16\n\t"
		"msr ttbr0_el1, x2\n\t"
		"isb\n\t"
		"bfi x2, %[ttbr0_el1], #0, #48\n\t"
		"msr ttbr0_el1, x2\n\t"
		"isb\n\t"
		: // empty output operand
		: [ttbr0_el1] "r" (args->a4)
		: "x2","x3"
	);
	args->a0 = TEE_SUCCESS;
}

static void tee_entry_rkp_erratum_cavium_27456 (struct thread_smc_args *args)
{
	__asm volatile (
		"ic	iallu\n\t"
		"dsb	nsh\n\t"
		"isb\n\t"
	);
	args->a0 = TEE_SUCCESS;
}

/* Note: this function is weak to let platforms add special handling */
void __weak tee_entry_fast(struct thread_smc_args *args)
{
	__tee_entry_fast(args);
}

/*
 * If tee_entry_fast() is overridden, it's still supposed to call this
 * function.
 */
void __tee_entry_fast(struct thread_smc_args *args)
{
	switch (args->a0) {

	/* Generic functions */
	case OPTEE_SMC_CALLS_COUNT:
		tee_entry_get_api_call_count(args);
		break;
	case OPTEE_SMC_CALLS_UID:
		tee_entry_get_api_uuid(args);
		break;
	case OPTEE_SMC_CALLS_REVISION:
		tee_entry_get_api_revision(args);
		break;
	case OPTEE_SMC_CALL_GET_OS_UUID:
		tee_entry_get_os_uuid(args);
		break;
	case OPTEE_SMC_CALL_GET_OS_REVISION:
		tee_entry_get_os_revision(args);
		break;

	/* OP-TEE specific SMC functions */
#ifdef CFG_CORE_RESERVED_SHM
	case OPTEE_SMC_GET_SHM_CONFIG:
		tee_entry_get_shm_config(args);
		break;
#endif
	case OPTEE_SMC_L2CC_MUTEX:
		tee_entry_fastcall_l2cc_mutex(args);
		break;
	case OPTEE_SMC_EXCHANGE_CAPABILITIES:
		tee_entry_exchange_capabilities(args);
		break;
	case OPTEE_SMC_DISABLE_SHM_CACHE:
		tee_entry_disable_shm_cache(args);
		break;
	case OPTEE_SMC_ENABLE_SHM_CACHE:
		tee_entry_enable_shm_cache(args);
		break;
	case OPTEE_SMC_BOOT_SECONDARY:
		tee_entry_boot_secondary(args);
		break;
	case OPTEE_SMC_GET_THREAD_COUNT:
		tee_entry_get_thread_count(args);
		break;

#if defined(CFG_VIRTUALIZATION)
	case OPTEE_SMC_VM_CREATED:
		tee_entry_vm_created(args);
		break;
	case OPTEE_SMC_VM_DESTROYED:
		tee_entry_vm_destroyed(args);
		break;
#endif

	case OPTEE_SMC_GPU_ASSIGN_MEMORY:
		tee_entry_gpu_map_memory (args);
		break;
	case OPTEE_SMC_GPU_GET_TZASC_REGION:
		tee_entry_gpu_get_tzasc_region (args);
		break;
	case OPTEE_SMC_GPU_SET_TZASC_REGION:
		tee_entry_gpu_set_tzasc_region (args);
		break;
	
	// RKP and its errata
	case OPTEE_SMC_RKP_SET_TTBR0_EL1:
		tee_entry_rkp_set_ttbr0_el1 (args);
		break;
	case OPTEE_SMC_RKP_ERRATUM_QCOM_FALKOR_1003:
		tee_entry_rkp_erratum_qcom_falkor_1003 (args);
		break;
	case OPTEE_SMC_RKP_ERRATUM_CAVIUM_27456:
		tee_entry_rkp_erratum_cavium_27456 (args);
		break;
	default:
		args->a0 = OPTEE_SMC_RETURN_UNKNOWN_FUNCTION;
		break;
	}
}

size_t tee_entry_generic_get_api_call_count(void)
{
	/*
	 * All the different calls handled in this file. If the specific
	 * target has additional calls it will call this function and
	 * add the number of calls the target has added.
	 */
	size_t ret = 12;

#if defined(CFG_VIRTUALIZATION)
	ret += 2;
#endif

	return ret;
}

void __weak tee_entry_get_api_call_count(struct thread_smc_args *args)
{
	args->a0 = tee_entry_generic_get_api_call_count();
}

void __weak tee_entry_get_api_uuid(struct thread_smc_args *args)
{
	args->a0 = OPTEE_MSG_UID_0;
	args->a1 = OPTEE_MSG_UID_1;
	args->a2 = OPTEE_MSG_UID_2;
	args->a3 = OPTEE_MSG_UID_3;
}

void __weak tee_entry_get_api_revision(struct thread_smc_args *args)
{
	args->a0 = OPTEE_MSG_REVISION_MAJOR;
	args->a1 = OPTEE_MSG_REVISION_MINOR;
}

void __weak tee_entry_get_os_uuid(struct thread_smc_args *args)
{
	args->a0 = OPTEE_MSG_OS_OPTEE_UUID_0;
	args->a1 = OPTEE_MSG_OS_OPTEE_UUID_1;
	args->a2 = OPTEE_MSG_OS_OPTEE_UUID_2;
	args->a3 = OPTEE_MSG_OS_OPTEE_UUID_3;
}

void __weak tee_entry_get_os_revision(struct thread_smc_args *args)
{
	args->a0 = CFG_OPTEE_REVISION_MAJOR;
	args->a1 = CFG_OPTEE_REVISION_MINOR;
	args->a2 = TEE_IMPL_GIT_SHA1;
}
