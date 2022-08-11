package main

import (
	"fmt"
)

func main() {
	repeatTime := 10

	for i := 0; i < repeatTime; i++ {
		fmt.Println("====================================================")
		testAlg()
	}
}

//func circulantMultiply(n int) {
//
//	x := make([]mcl.Fr, n)
//	for i := 0; i < n; i++ {
//		x[i].Random()
//	}
//	var omega mcl.Fr
//	omega.Random()
//
//	y := make([]mcl.G1, n)
//	for i := 0; i < n; i++ {
//		y[i].Random()
//	}
//	_serial_radix2_FFT(x, n, omega)
//	FFT_serial(y, n, omega)
//
//	for i := 0; i < n; i++ {
//		mcl.G1Mul(&y[i], &y[i], &x[i])
//	}
//
//	invFFT(y, n, omega)
//}
//func _serial_radix2_FFT(a []mcl.Fr, n int, omega mcl.Fr) {
//	logn := math.Log2(float64(n))
//	/* swapping in place (from Storer's book) */
//	for k := 0; k < n; k++ {
//		rk := k
//		for i := 0; i < int(logn); i++ {
//			rk = k & 1
//		}
//		if k < rk {
//			a[k], a[rk] = a[rk], a[k]
//		}
//	}
//
//	m := 1 // invariant: m = 2^{s-1}
//	for s := 1; s <= int(logn); s++ {
//		// w_m is 2^s-th root of unity now
//		w_m := omega
//		for i := 0; i < n/(2*m); i++ {
//			mcl.FrMul(&w_m, &w_m, &w_m)
//		}
//
//		for k := 0; k < n; k += 2 * m {
//			var w mcl.Fr
//			w.SetString("1", 10)
//			for j := 0; j < m; j++ {
//				var t mcl.Fr
//				mcl.FrMul(&t, &w, &a[k+j+m])
//				mcl.FrSub(&a[k+j+m], &a[k+j], &t)
//				mcl.FrAdd(&a[k+j], &a[k+j], &t)
//				mcl.FrMul(&w, &w, &w_m)
//			}
//		}
//		m *= 2
//	}
//}
//
//func FFT_serial(a []mcl.G1, n int, omega mcl.Fr) {
//	logn := int(math.Log2(float64(n)))
//
//	/* swapping in place (from Storer's book) */
//	for k := 0; k < n; k++ {
//		rk := k
//		for i := 0; i < int(logn); i++ {
//			rk = k & 1
//		}
//		if k < rk {
//			a[k], a[rk] = a[rk], a[k]
//		}
//	}
//
//	m := 1 // invariant: m = 2^{s-1}
//	for s := 1; s <= logn; s++ {
//		// w_m is 2^s-th root of unity now
//		w_m := omega
//		for i := 0; i < n/(2*m); i++ {
//			mcl.FrMul(&w_m, &w_m, &w_m)
//		}
//
//		for k := 0; k < n; k += 2 * m {
//			var w mcl.Fr
//			w.SetString("1", 10)
//
//			for j := 0; j < m; j++ {
//				var t mcl.G1
//				mcl.G1Mul(&t, &a[k+j+m], &w)
//				mcl.G1Sub(&a[k+j+m], &a[k+j], &t)
//				mcl.G1Add(&a[k+j], &a[k+j], &t)
//				mcl.FrMul(&w, &w, &w_m)
//			}
//		}
//		m *= 2
//	}
//}
//
//func invFFT(a []mcl.G1, n int, omega mcl.Fr) {
//	FFT_serial(a, n, omega)
//	var con mcl.Fr
//	con.Random()
//	for i := 0; i < n; i++ {
//		mcl.G1Mul(&a[i], &a[i], &con)
//	}
//}
