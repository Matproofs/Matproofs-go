package main

import "github.com/alinush/go-mcl"

/// generate a new global commitment.
func (com *GlobalCommitment) NewGlocalCommitment(pp PublicParams, values []mcl.Fr) {
	rearrange_alpha_beta_vec := make([]mcl.G1, pp.n*pp.n)
	for i := 0; i < pp.n; i++ {
		for j := 0; j < pp.n; j++ {
			rearrange_alpha_beta_vec[i*pp.n+j] = pp.pp_generators_alpha_beta[j][i]
		}
	}

	//global_commitment=g_1^{\sum_{i\in[N]}\sum_{j\in[N]}m_{ij}\alpha^j\beta^i}
	mcl.G1MulVec(&com.global_commitment, rearrange_alpha_beta_vec, values)
}

/// generate a new local commitment.
func (com *LocalCommitment) NewLocalCommitment(pp PublicParams, values []mcl.Fr) {
	//com.local_commitment = make([]mcl.G1, pp.n)
	//for i := 0; i < pp.n; i++ {
	mcl.G1MulVec(&com.local_commitment, pp.pp_generators_alpha[0:pp.n], values)
	//}
}

/// updated an existing global commitment
func (com *GlobalCommitment) UpdateGlobalCommitment(
	pp PublicParams,
	changedIndex []int,
	deltaValue mcl.Fr) {
	var res_c2 mcl.G1
	mcl.G1Mul(&res_c2, &pp.pp_generators_alpha_beta[changedIndex[0]][changedIndex[1]], &deltaValue)
	mcl.G1Add(&com.global_commitment, &com.global_commitment, &res_c2)
}

/// updated an existing local commitment
func (com *LocalCommitment) UpdateLocalCommitment(
	pp PublicParams,
	changedIndex []int,
	deltaValue mcl.Fr) {
	var resci mcl.G1
	mcl.G1Mul(&resci, &pp.pp_generators_alpha[changedIndex[1]], &deltaValue)
	mcl.G1Add(&com.local_commitment, &com.local_commitment, &resci)
}
