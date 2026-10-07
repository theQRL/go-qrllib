package falcon1024

import (
	"bytes"
	"crypto/sha3"
	"strconv"
	"testing"
)

func TestSHAKE256KAT(t *testing.T) {
	// Falcon uses SHAKE256 for hashing to a point and for seeding. It comes
	// from the standard library, so these known-answer vectors pin the
	// assumption that it produces the expected stream, whether data is
	// processed in one call or byte by byte.
	testCases := []struct {
		in  string
		out string
	}{
		{
			in: "",
			out: "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f" +
				"d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
		},
		{
			in: "dc5a100fa16df1583c79722a0d72833d3bf22c109b8889dbd35213c6bfce2058" +
				"13edae3242695cfd9f59b9a1c203c1b72ef1a5423147cb990b5316a852666758" +
				"94e2644c3f9578cebe451a09e58c53788fe77a9e850943f8a275f830354b0593" +
				"a762bac55e984db3e0661eca3cb83f67a6fb348e6177f7dee2df40c4322602f0" +
				"94953905681be3954fe44c4c902c8f6bba565a788b38f13411ba76ce0f9f6756" +
				"a2a2687424c5435a51e62df7a8934b6e141f74c6ccf539e3782d22b5955d3baf" +
				"1ab2cf7b5c3f74ec2f9447344e937957fd7f0bdfec56d5d25f61cde18c0986e2" +
				"44ecf780d6307e313117256948d4230ebb9ea62bb302cfe80d7dfebabc4a51d7" +
				"687967ed5b416a139e974c005fff507a96",
			out: "2bac5716803a9cda8f9e84365ab0a681327b5ba34fdedfb1c12e6e807f45284b",
		},
		{
			in: "8d8001e2c096f1b88e7c9224a086efd4797fbf74a8033a2d422a2b6b8f6747e4",
			out: "2e975f6a8a14f0704d51b13667d8195c219f71e6345696c49fa4b9d08e9225d3" +
				"d39393425152c97e71dd24601c11abcfa0f12f53c680bd3ae757b8134a9c10d4" +
				"29615869217fdd5885c4db174985703a6d6de94a667eac3023443a8337ae1bc6" +
				"01b76d7d38ec3c34463105f0d3949d78e562a039e4469548b609395de5a4fd43" +
				"c46ca9fd6ee29ada5efc07d84d553249450dab4a49c483ded250c9338f85cd93" +
				"7ae66bb436f3b4026e859fda1ca571432f3bfc09e7c03ca4d183b741111ca048" +
				"3d0edabc03feb23b17ee48e844ba2408d9dcfd0139d2e8c7310125aee801c61a" +
				"b7900d1efc47c078281766f361c5e6111346235e1dc38325666c",
		},
	}

	for i, tc := range testCases {
		t.Run("vector-"+strconv.Itoa(i), func(t *testing.T) {
			in := mustDecodeHex(t, tc.in)
			want := mustDecodeHex(t, tc.out)

			sc := sha3.NewSHAKE256()
			_, _ = sc.Write(in)
			got := make([]byte, len(want))
			_, _ = sc.Read(got)
			if !bytes.Equal(got, want) {
				t.Fatalf("one-shot output = %x, want %x", got, want)
			}

			sc = sha3.NewSHAKE256()
			for j := range in {
				_, _ = sc.Write(in[j : j+1])
			}
			clear(got)
			for j := range got {
				_, _ = sc.Read(got[j : j+1])
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("byte-by-byte output = %x, want %x", got, want)
			}
		})
	}
}
