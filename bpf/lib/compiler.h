#ifndef __BPF_COMPILER_H_
#define __BPF_COMPILER_H_

/* Unfortunately verifier forces aligned stack access while other memory
 * do not have to be aligned (map, pkt, etc). Mark those on the /stack/
 * for objects > 8 bytes in order to force-align such memcpy candidates
 * when we really need them to be aligned, this is not needed for objects
 * of size <= 8 bytes and in case of > 8 bytes /only/ when 8 byte is not
 * the natural object alignment (e.g. __u8 foo[12]).
 */
#define __align_stack_8		__aligned(8)

/* Memory iterators used below. */
#define __it_bwd(x, op) (x -= sizeof(__u##op))
#define __it_fwd(x, op) (x += sizeof(__u##op))

/* Memory operators used below. */
#define __it_set(a, op) (*(__u##op *)__it_bwd(a, op)) = 0
#define __it_xor(a, b, r, op) r |= (*(__u##op *)__it_bwd(a, op)) ^ (*(__u##op *)__it_bwd(b, op))
#define __it_mob(a, b, op) (*(__u##op *)__it_bwd(a, op)) = (*(__u##op *)__it_bwd(b, op))

#ifndef __non_bpf_context
# include "stddef.h"
#endif

#ifndef __section
# define __section(X)		__attribute__((section(X), used))
#endif

#ifndef __maybe_unused
# define __maybe_unused		__attribute__((__unused__))
#endif

#ifndef offsetof
# define offsetof(T, M)		__builtin_offsetof(T, M)
#endif

#ifndef field_sizeof
# define field_sizeof(T, M)	sizeof((((T *)NULL)->M))
#endif

#ifndef __packed
# define __packed		__attribute__((packed))
#endif

#ifndef __nobuiltin
# if __clang_major__ >= 10
#  define __nobuiltin(X)	__attribute__((no_builtin(X)))
# else
#  define __nobuiltin(X)
# endif
#endif

#ifndef likely
# define likely(X)		__builtin_expect(!!(X), 1)
#endif

#ifndef unlikely
# define unlikely(X)		__builtin_expect(!!(X), 0)
#endif

#ifndef always_succeeds		/* Mainly for documentation purpose. */
# define always_succeeds(X)	likely(X)
#endif

#undef __always_inline		/* stddef.h defines its own */
#define __always_inline		inline __attribute__((always_inline))

#ifndef __stringify
# define __stringify(X)		#X
#endif

#ifndef __fetch
# define __fetch(X)		(__u32)(__u64)(&(X))
#endif

#ifndef __aligned
# define __aligned(X)		__attribute__((aligned(X)))
#endif

#ifndef build_bug_on
# define build_bug_on(E)	((void)sizeof(char[1 - 2*!!(E)]))
#endif

#ifndef __throw_build_bug
# define __throw_build_bug()	__builtin_trap()
#endif

#ifndef __printf
# define __printf(X, Y)		__attribute__((__format__(printf, X, Y)))
#endif

#ifndef barrier
# define barrier()		asm volatile("": : :"memory")
#endif

#ifndef barrier_data
# define barrier_data(ptr)	asm volatile("": :"r"(ptr) :"memory")
#endif

static __always_inline void bpf_barrier(void)
{
	/* Workaround to avoid verifier complaint:
	 * "dereference of modified ctx ptr R5 off=48+0, ctx+const is allowed,
	 *        ctx+const+const is not"
	 */
	barrier();
}

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(A)		(sizeof(A) / sizeof((A)[0]))
#endif

#ifndef __READ_ONCE
# define __READ_ONCE(X)		(*(volatile typeof(X) *)&X)
#endif

#ifndef __WRITE_ONCE
# define __WRITE_ONCE(X, V)	(*(volatile typeof(X) *)&X) = (V)
#endif

/* {READ,WRITE}_ONCE() with verifier workaround via bpf_barrier(). */

#ifndef READ_ONCE
# define READ_ONCE(X)						\
			({ typeof(X) __val = __READ_ONCE(X);	\
			   bpf_barrier();			\
			   __val; })
#endif

#ifndef WRITE_ONCE
# define WRITE_ONCE(X, V)					\
				({ typeof(X) __val = (V);	\
				   __WRITE_ONCE(X, __val);	\
				   bpf_barrier();		\
				   __val; })
#endif

#ifndef __section_tail
# define __section_tail(ID, KEY)	__section(__stringify(ID) "/" __stringify(KEY))
#endif

#ifndef __section_license
# define __section_license		__section("license")
#endif

#ifndef __section_maps
# define __section_maps			__section("maps")
#endif

#ifndef __section_maps_btf
# define __section_maps_btf		__section(".maps")
#endif

// char __license[] SEC("license") = "Dual MIT/GPL";
#ifndef BPF_LICENSE
# define BPF_LICENSE(NAME) char __license[] SEC("license") = NAME
#endif

#ifndef BPF_MAP
# define BPF_MAP bpf_map_def __attribute__((section("maps"), used))
#endif

#ifndef BPF_INLINE
# define BPF_INLINE static __always_inline
#endif

BPF_INLINE __u64 __bpf_memcmp(const void *x, const void *y, __u64 len)
{
	__u64 r = 0;

	if (!__builtin_constant_p(len))
		__throw_build_bug();

	x += len;
	y += len;

	switch (len) {
	case 32:         __it_xor(x, y, r, 64);
	case 24: jmp_24: __it_xor(x, y, r, 64);
	case 16: jmp_16: __it_xor(x, y, r, 64);
	case  8: jmp_8:  __it_xor(x, y, r, 64);
		break;

	case 30: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_24;
	case 22: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_16;
	case 14: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_8;
	case  6: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32);
		break;

	case 28: __it_xor(x, y, r, 32); goto jmp_24;
	case 20: __it_xor(x, y, r, 32); goto jmp_16;
	case 12: __it_xor(x, y, r, 32); goto jmp_8;
	case  4: __it_xor(x, y, r, 32);
		break;

	case 26: __it_xor(x, y, r, 16); goto jmp_24;
	case 18: __it_xor(x, y, r, 16); goto jmp_16;
	case 10: __it_xor(x, y, r, 16); goto jmp_8;
	case  2: __it_xor(x, y, r, 16);
		break;

	case  1: __it_xor(x, y, r, 8);
		break;

	default:
		__throw_build_bug();
	}

	return r;
}

#endif /* __BPF_COMPILER_H_ */
