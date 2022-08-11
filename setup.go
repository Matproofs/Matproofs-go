package main

import (
	"github.com/alinush/go-mcl"
)

func (pp *PublicParams) Paramgen(N int) {
	pp.n = N
	pp.pp_generators_alpha = make([]mcl.G1, 2*pp.n)
	pp.pp_generators_alpha_beta = make([][]mcl.G1, pp.n)
	for i := 0; i < pp.n; i++ {
		pp.pp_generators_alpha_beta[i] = make([]mcl.G1, 2*pp.n)
	}
	pp.vp_generators_alpha = make([]mcl.G2, pp.n)
	pp.vp_generators_beta = make([]mcl.G2, pp.n+1)

	var alpha, beta, alpha_power, beta_power mcl.Fr

	alpha.Random()
	beta.Random()
	alpha_power.SetInt64(1)
	beta_power.SetInt64(1)

	//pp.g1.Random()
	//pp.g2.Random()

	pp.g1.HashAndMapTo(IntToBytes(1))
	pp.g2.HashAndMapTo(IntToBytes(1))

	for i := 0; i < pp.n; i++ {
		//fmt.Println("i=", i)

		mcl.FrMul(&alpha_power, &alpha_power, &alpha) //compute alpha^i
		mcl.G1Mul(&pp.pp_generators_alpha[i], &pp.g1, &alpha_power)
		mcl.G2Mul(&pp.vp_generators_alpha[i], &pp.g2, &alpha_power)

		alpha_beta_power := alpha_power
		for j := 0; j < pp.n; j++ {
			mcl.FrMul(&alpha_beta_power, &alpha_beta_power, &beta) //compute alpha^i beta^j
			mcl.G1Mul(&pp.pp_generators_alpha_beta[i][j], &pp.g1, &alpha_beta_power)
		}
		//skip g1^{alpha^i beta^{n+1}}
		mcl.FrMul(&alpha_beta_power, &alpha_beta_power, &beta)
		pp.pp_generators_alpha_beta[i][pp.n].SetString("0", 10)

		for j := pp.n + 1; j < 2*pp.n; j++ {
			mcl.FrMul(&alpha_beta_power, &alpha_beta_power, &beta) //compute alpha^i beta^j
			mcl.G1Mul(&pp.pp_generators_alpha_beta[i][j], &pp.g1, &alpha_beta_power)
		}

		mcl.FrMul(&beta_power, &beta_power, &beta)
		mcl.G2Mul(&pp.vp_generators_beta[i], &pp.g2, &beta_power)
	}

	//skip g1^{alpha^{n+1}}
	mcl.FrMul(&alpha_power, &alpha_power, &alpha)
	pp.pp_generators_alpha[pp.n].SetString("0", 10)

	//compute g2^{beta^{n+1}}
	mcl.FrMul(&beta_power, &beta_power, &beta)
	mcl.G2Mul(&pp.vp_generators_beta[pp.n], &pp.g2, &beta_power)

	for i := pp.n + 1; i < 2*pp.n; i++ {
		mcl.FrMul(&alpha_power, &alpha_power, &alpha) //compute alpha^i beta^j
		mcl.G1Mul(&pp.pp_generators_alpha[i], &pp.g1, &alpha_power)
	}

	mcl.Pairing(&pp.vp_gt_elt, &pp.pp_generators_alpha[0], &pp.vp_generators_alpha[pp.n-1])
}
