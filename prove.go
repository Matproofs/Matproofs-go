package main

import (
	"fmt"
	"github.com/alinush/go-mcl"
)

//generate a new inner proof
func (pr *InnerProof) NewInnerProof(
	pp PublicParams,
	values []mcl.Fr,
	indexj int,
) {
	if indexj >= pp.n {
		fmt.Println("Invalid Index-NewInnerProof")
		return
	}
	mcl.G1MulVec(&pr.inner_proof_content, pp.pp_generators_alpha[pp.n-indexj:2*pp.n-indexj], values)
}

//update an inner proof
func (pr *InnerProof) UpdateInnerProof(
	pp PublicParams,
	proof_index []int,
	changed_index []int,
	delta_value mcl.Fr,
) {
	if proof_index[0] != changed_index[0] {
		fmt.Println("Only inner proof in the same row needs updating")
		return
	}
	if proof_index[0] >= pp.n || proof_index[1] >= pp.n || changed_index[1] >= pp.n {
		fmt.Println("Invalid Index")
		return
	}
	//j!=k
	if proof_index[1] != changed_index[1] {
		param_index := pp.n + changed_index[1] - proof_index[1] //n+k-j
		var res mcl.G1
		mcl.G1Mul(&res, &pp.pp_generators_alpha[param_index], &delta_value)
		mcl.G1Add(&pr.inner_proof_content, &pr.inner_proof_content, &res)
	}
}

//Aggregate a 2-dim array of proofs
func AggregateInnerProof(
	commits []mcl.G1, //C1[R(S)]
	proofs [][]InnerProof, //\pi_{ij}
	set [][]int, //S
	value_sub_vector [][]mcl.Fr, //M[S]
	n int,
) InnerProof {
	for i := 0; i < len(set); i++ {
		for j := 0; j < len(set[i]); j++ {
			if set[i][j] >= n {
				fmt.Println("Invalid index")
			}
		}
	}
	if len(commits) != len(proofs) || len(commits) != len(set) || len(commits) != len(value_sub_vector) || len(commits) == 0 {
		fmt.Println("Mismatch size")
	}

	ti := dim2Hash(commits, set, value_sub_vector, n)

	ti_s := make([][]mcl.Fr, len(commits))
	for i := 0; i < len(commits); i++ {
		ti_s[i] = dim1Hash(commits[i], set[i], value_sub_vector[i], n)
	}

	var scalars []mcl.Fr
	var proofBases []mcl.G1

	//form the final scalars by multiplying ti[i]*ti_s[i, j]
	for i := 0; i < len(ti); i++ {
		for j := 0; j < len(ti_s[i]); j++ {
			var tmp mcl.Fr
			mcl.FrMul(&tmp, &ti_s[i][j], &ti[i])
			scalars = append(scalars, tmp)
			proofBases = append(proofBases, proofs[i][j].inner_proof_content)
		}
	}
	var res mcl.G1
	mcl.G1MulVec(&res, proofBases, scalars)
	return InnerProof{res}
}

//verify the single inner proof
func (pr InnerProof) VerifySingleInnerProof(
	pp PublicParams,
	com mcl.G1,
	value mcl.Fr,
	index int,
) bool {
	if index >= pp.n {
		fmt.Println("Invalid Index")
		return false
	}

	// verification formula: e(com, param[n-index.1-1]) = gt_elt ^ value * e(proof, generator_of_g2)
	// which is to check
	// e(com^hash_inverse,  param[n-index.1-1]) * e(proof^{-hash_inverse}, generator_of_g2)?= gt_elt

	//var lhs, gtPower, pair1, rhs mcl.GT
	//mcl.Pairing(&lhs, &com, &pp.vp_generators_alpha[pp.n-index-1])
	//mcl.GTPow(&gtPower, &pp.vp_gt_elt, &value)
	//mcl.Pairing(&pair1, &pr.inner_proof_content, &pp.g2)
	//mcl.GTMul(&rhs, &gtPower, &pair1)
	//mcl.FinalExp(&lhs, &lhs)
	//mcl.FinalExp(&rhs, &rhs)
	//fmt.Println(lhs.IsEqual(&rhs))

	//step 1, compute valueInverse
	var valueInverse mcl.Fr
	mcl.FrInv(&valueInverse, &value)

	// step 2, compute com^hash_inverse and proof^{-hash_inverse}
	var proof_negate, proof_mut, com_mut mcl.G1
	mcl.G1Neg(&proof_negate, &pr.inner_proof_content)
	mcl.G1Mul(&proof_mut, &proof_negate, &valueInverse)
	mcl.G1Mul(&com_mut, &com, &valueInverse)

	// step 3. check pairing product
	g1Vec := make([]mcl.G1, 2)
	g2Vec := make([]mcl.G2, 2)

	g1Vec[0] = com_mut
	g2Vec[0] = pp.vp_generators_alpha[pp.n-index-1]
	g1Vec[1] = proof_mut
	g2Vec[1] = pp.g2

	var lhs mcl.GT

	mcl.MillerLoopVec(&lhs, g1Vec, g2Vec)
	mcl.FinalExp(&lhs, &lhs)

	return pp.vp_gt_elt.IsEqual(&lhs)
}

// Verify inner proofs which were aggregated from 2-dim array of proofs
func (proof InnerProof) BatchVerifyInnerProof(
	pp PublicParams,
	commits []mcl.G1, //C1[R(S)]
	set [][]int, //S
	value_sub_vector [][]mcl.Fr, //M[S]
) bool {
	num_commit := len(commits)
	if num_commit != len(set) || num_commit != len(value_sub_vector) || num_commit == 0 {
		fmt.Println("length does not match")
		return false
	}
	for j := 0; j < num_commit; j++ {
		if len(set[j]) != len(value_sub_vector[j]) || len(set[j]) == 0 || len(set[j]) > pp.n {
			fmt.Println("length does not match")
			return false
		}
	}
	//generate ti_s
	ti_s := make([][]mcl.Fr, num_commit)
	for j := 0; j < num_commit; j++ {
		ti_s[j] = dim1Hash(commits[j], set[j], value_sub_vector[j], pp.n)
	}
	//generate ti
	ti := dim2Hash(commits, set, value_sub_vector, pp.n)

	// we want to check
	//  \prod_{i=1}^num_commit e(com[i], g2^{\sum alpha^{n + 1 -j} * t_i,j} ) ^ t_i
	//      ?= e (proof, g2) * e (g1, g2)^{alpha^{n+1} * {\sum m_i,j * t_i,j * ti}}
	// step 1. compute tmp = \sum m_i,j * t_i,j * ti
	var tmp mcl.Fr
	tmp.SetInt64(0)
	for j := 0; j < num_commit; j++ {
		var tmp2 mcl.Fr
		tmp2.SetInt64(0)

		// tmp2 = sum_i m_ij * t_ij
		for k := 0; k < len(ti_s[j]); k++ {
			tmp3 := ti_s[j][k]
			mcl.FrMul(&tmp3, &tmp3, &value_sub_vector[j][k])
			mcl.FrAdd(&tmp2, &tmp2, &tmp3)
		}
		// tmp2 = tj * tmp2
		mcl.FrMul(&tmp2, &tmp2, &ti[j])
		// tmp += tj * (sum_i m_ji * t_ij)
		mcl.FrAdd(&tmp, &tmp, &tmp2)
	}

	var tmpInverse mcl.Fr
	mcl.FrInv(&tmpInverse, &tmp)

	// step 2. now the formula becomes
	// \prod e(com[i], g2^{\sum alpha^{n + 1 - j} * t_i,j * ti/tmp} )
	//  * e(proof^{-1/tmp}, g2)
	//  ?= e(g1, g2)^{alpha^{n+1}} == verifier_params.gt_elt

	//g1_vec stores the g1 components for the pairing product
	//for j \in [num_commit], store com[j]
	g1Vec := make([]mcl.G1, num_commit+1)
	for i := 0; i < num_commit; i++ {
		g1Vec[i] = commits[i]
	}
	// the last element for g1_vec is proof^{-1/tmp}
	var proofNeg mcl.G1
	mcl.G1Neg(&proofNeg, &proof.inner_proof_content)
	mcl.G1Mul(&proofNeg, &proofNeg, &tmpInverse)
	g1Vec[num_commit] = proofNeg

	// g2_vec stores the g2 components for the pairing product
	// for j \in [num_commit], g2^{\sum alpha^{n + 1 - j} * t_i,j} * ti/tmp )
	g2Vec := make([]mcl.G2, num_commit+1)
	for j := 0; j < num_commit; j++ {
		num_proof := len(ti_s[j])
		tmp3 := tmpInverse

		mcl.FrMul(&tmp3, &tmp3, &ti[j])

		// subset_sum = \sum alpha^{n + 1 - j} * t_i,j}
		bases := make([]mcl.G2, num_proof)
		scalars := make([]mcl.Fr, num_proof)
		for k := 0; k < num_proof; k++ {
			bases[k] = pp.vp_generators_alpha[pp.n-set[j][k]-1]
			t := ti_s[j][k]
			mcl.FrMul(&t, &t, &tmp3)
			scalars[k] = t
		}
		var sum mcl.G2
		mcl.G2MulVec(&sum, bases, scalars)

		g2Vec[j] = sum
	}
	// the last element for g1_vec is g2
	g2Vec[num_commit] = pp.g2

	var lhs mcl.GT
	mcl.MillerLoopVec(&lhs, g1Vec, g2Vec)
	mcl.FinalExp(&lhs, &lhs)
	return pp.vp_gt_elt.IsEqual(&lhs)
}

/*Outer Proof*/
//generate a new outer proof
func (pr *OuterProof) NewOuterProof(
	pp PublicParams,
	values []mcl.Fr,
	index int,
) {
	if index >= pp.n {
		fmt.Println("Invalid index-NewOuterProof")
		return
	}
	if len(values) != pp.n*pp.n {
		fmt.Println("Invalid vector size-NewOuterProof")
		return
	}
	new_beta_alpha_power := make([]mcl.G1, pp.n*pp.n)
	for j := 0; j < pp.n; j++ {
		for k := 0; k < pp.n; k++ {
			new_beta_alpha_power[j*pp.n+k] = pp.pp_generators_alpha_beta[k*(2*pp.n)+pp.n-index+j]
		}
	}

	//Compute proofOuter: \pi_i=g_1^{\sum_{j\in[N]}\sum_{k\in[N]}m_{jk}\alpha^k\beta^{N+1-i+j}}
	mcl.G1MulVec(&pr.outer_proof_content, new_beta_alpha_power, values)
}

//Updating an existing outer proof
func (pr *OuterProof) UpdateOuterProof(
	pp PublicParams,
	proof_index int,
	changed_index []int,
	delta_value mcl.Fr) {
	// check indices are valid
	if proof_index >= pp.n || changed_index[0] >= pp.n || changed_index[1] >= pp.n {
		fmt.Println("Invalid Index-updateOuterProof")
	}

	// j!=i
	if proof_index != changed_index[0] {
		param_index := changed_index[0] + pp.n - proof_index //N+1-j+i
		var res mcl.G1
		mcl.G1Mul(&res, &pp.pp_generators_alpha_beta[changed_index[1]*(2*pp.n)+param_index], &delta_value)
		//\pi'_j=\pi_j\cdot g_1^{\Delta m_{ik}\alpha^k\beta^{N+1-j+i}}.
		mcl.G1Add(&pr.outer_proof_content, &pr.outer_proof_content, &res)
	}
}

// Aggregates a vector of outer proofs into a single one
func AggregateOuterProof(
	commit mcl.G1,
	proofs []OuterProof,
	set []int,
	inner_commitment_sub_vector []mcl.G1,
	n int,
) OuterProof {
	// check that the length of proofs and sets match
	if len(proofs) != len(set) || len(proofs) != len(inner_commitment_sub_vector) {
		fmt.Println("Mismatch length-aggregateOuterproof")
	}
	ti := dim1HashWithGelement(commit, set, inner_commitment_sub_vector, n)

	proofsSize := len(proofs)
	bases := make([]mcl.G1, proofsSize)
	for i := 0; i < proofsSize; i++ {
		bases[i] = proofs[i].outer_proof_content
	}

	var res mcl.G1
	mcl.G1MulVec(&res, bases, ti)
	return OuterProof{res}
}

//Verify the single outer proof
func (pr OuterProof) VerifySingleOuterProof(
	pp PublicParams,
	com mcl.G1,
	inner_commit_value mcl.G1,
	index int) bool {

	if index >= pp.n {
		return false
	}

	// verification formula: e(com, beta_param[n-index-1]) = e(proof, generator_of_g2) * e(inner_commit_value, g2^{\beta^{N+1}})

	//step 1. compute LHS with inner function Bls12::pairing_product
	var lhs, rhs mcl.GT
	mcl.Pairing(&lhs, &com, &pp.vp_generators_beta[pp.n-index-1])

	//step 2. compute RHS
	g1Vec := make([]mcl.G1, 2)
	g2Vec := make([]mcl.G2, 2)
	g1Vec[0] = pr.outer_proof_content
	g2Vec[0] = pp.g2
	g1Vec[1] = inner_commit_value
	g2Vec[1] = pp.vp_generators_beta[pp.n]

	mcl.MillerLoopVec(&rhs, g1Vec, g2Vec)
	mcl.FinalExp(&rhs, &rhs)

	return lhs.IsEqual(&rhs)
}

// batch verify a proof for a list of values/indices
func (pr OuterProof) BatchVerifyOuterProof(
	pp PublicParams,
	com mcl.G1,
	set []int,
	inner_commitment_sub_vector []mcl.G1,
) bool {
	// we want to check if
	//   e(com, g2^{\sum_{i \in set} \beta^{N+1-i} t_i})
	//    ?= e(proof, g2) * \Prod_{i\in set} e(c_i^{t_i}, g2^{\beta^{N+1}})

	// 0. check the validity of the inputs: csid, length, etc
	if len(set) != len(inner_commitment_sub_vector) {
		return false
	}
	if len(inner_commitment_sub_vector) > pp.n {
		return false
	}
	for _, e := range set {
		if e >= pp.n {
			return false
		}
	}

	// if the length == 1, call normal verification method
	//if len(set) == 1 {
	//	return pr.VerifySingleOuterProof(pp, com, inner_commitment_sub_vector[0], set[0])
	//}

	// 1. compute t_i
	// 1.1 get the list of scalas, return false if this failed
	ti := dim1HashWithGelement(com, set, inner_commitment_sub_vector, pp.n)

	// 1.2 g2^{\sum_{i \in set} \beta^{N+1-i} t_i}
	setSize := len(set)
	bases := make([]mcl.G2, setSize)

	for i := 0; i < setSize; i++ {
		bases[i] = pp.vp_generators_beta[pp.n-i-1]
	}

	var param_subset_sum mcl.G2
	mcl.G2MulVec(&param_subset_sum, bases, ti)

	var lhs, rhs mcl.GT
	mcl.Pairing(&lhs, &com, &param_subset_sum)
	// 2 compute RHS=e(proof, g2) * \Prod_{i\in set} e(c_i^{t_i}, g2^{\beta^{N+1}})
	// 2.1
	g1Vec := make([]mcl.G1, setSize+1)
	g2Vec := make([]mcl.G2, setSize+1)

	g1Vec[0] = pr.outer_proof_content
	g2Vec[0] = pp.g2

	for i := 1; i <= setSize; i++ {
		mcl.G1Mul(&g1Vec[i], &inner_commitment_sub_vector[i-1], &ti[i-1])
		g2Vec[i] = pp.vp_generators_beta[pp.n]
	}

	mcl.MillerLoopVec(&rhs, g1Vec, g2Vec)
	mcl.FinalExp(&rhs, &rhs)
	return lhs.IsEqual(&rhs)
}
