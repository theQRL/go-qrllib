package dilithium

func powerToRound(a uint32, a0 *uint32) uint32 {
	t := int32(a & ((1 << D) - 1))
	t -= (1 << (D - 1)) + 1
	t += (t >> 31) & (1 << D)
	t -= (1 << (D - 1)) - 1
	*a0 = uint32(Q + t)
	a = (a - uint32(t)) >> D
	return a
}

func decompose(a uint32, a0 *uint32) uint32 {
	if ALPHA != (Q-1)/16 {
		panic("decompose assumes ALPHA == (Q-1)/16")
	}
	/* Centralized remainder mod ALPHA */
	t := int32(a & 0x7FFFF)
	t += int32((a >> 19) << 9)
	t -= ALPHA/2 + 1
	t += (t >> 31) & ALPHA
	t -= ALPHA/2 - 1
	a -= uint32(t)

	/* Divide by ALPHA (possible to avoid) */
	u := int32(a - 1)
	u >>= 31
	a = (a >> 19) + 1
	a -= uint32(u & 1)

	/* Border case */
	*a0 = uint32(Q + t - int32(a>>4))
	a &= 0xF
	return a
}

func makeHint(a, b uint32) uint32 {
	// XXX FIXME: check if vartime bears significance in here
	var t uint32
	x := decompose(a, &t)
	y := decompose(freeze(a+b), &t)
	if x != y {
		return 1
	} else {
		return 0
	}
}

func useHint(a uint32, hint uint32) uint32 {
	var a0, a1 uint32

	a1 = decompose(a, &a0)
	if hint == 0 {
		return a1
	} else if a0 > Q {
		if a1 == (Q-1)/ALPHA-1 {
			return 0
		} else {
			return a1 + 1
		}
	} else {
		if a1 == 0 {
			return (Q-1)/ALPHA - 1
		} else {
			return a1 - 1
		}
	}

	/* If decompose does not divide out ALPHA:
	if(hint == 0)
	  return a1;
	else if(a0 > Q)
	  return (a1 == Q - 1 - ALPHA) ? 0 : a1 + ALPHA;
	else
	  return (a1 == 0) ? Q - 1 - ALPHA : a1 - ALPHA;
	*/
}
