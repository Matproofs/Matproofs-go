package main

import "github.com/alinush/go-mcl"

/// generate a new commitment.
func (com *Commitment) New(pp PublicParams, values []mcl.Fr) {
	rearrange_alpha_beta_vec := make([]mcl.G1, pp.n*pp.n)
	for i := 0; i < pp.n; i++ {
		for j := 0; j < pp.n; j++ {
			rearrange_alpha_beta_vec[i*pp.n+j] = pp.pp_generators_alpha_beta[j*(2*pp.n)+i]
		}
	}

	//C_2=g_1^{\sum_{i\in[N]}\sum_{j\in[N]}m_{ij}\alpha^j\beta^i}
	mcl.G1MulVec(&com.commit_c2, rearrange_alpha_beta_vec, values)

	//C1=(c_1, ..., c_n)
	com.commit_c1 = make([]mcl.G1, pp.n)
	for i := 0; i < pp.n; i++ {
		mcl.G1MulVec(&com.commit_c1[i], pp.pp_generators_alpha[0:pp.n], values[i*pp.n:(i+1)*pp.n])
	}
}

/// updated an existing outer commitment
func (com *Commitment) UpdateOuterCommitment(
	pp PublicParams,
	changedIndex []int,
	deltaValue mcl.Fr) {
	var res_c2 mcl.G1
	mcl.G1Mul(&res_c2, &pp.pp_generators_alpha_beta[changedIndex[0]*(2*pp.n)+changedIndex[1]], &deltaValue)
	mcl.G1Add(&com.commit_c2, &com.commit_c2, &res_c2)
}

/// updated an existing inner commitment
func (com *Commitment) UpdateInnerCommitment(
	pp PublicParams,
	changedIndex []int,
	deltaValue mcl.Fr) {
	var resci mcl.G1
	mcl.G1Mul(&resci, &pp.pp_generators_alpha[changedIndex[1]], &deltaValue)
	mcl.G1Add(&com.commit_c1[changedIndex[0]], &com.commit_c1[changedIndex[0]], &resci)
}
