package main

import (
	"fmt"
	"github.com/alinush/go-mcl"
	"time"
)

/*Test all algorithms*/
func testAlg() {
	N := 2048

	outerSize := 32
	innerSize := 32

	mcl.InitFromString("bls12-381")

	//prepare matrix M
	values := make([]mcl.Fr, N*N)
	for i := 0; i < N*N; i++ {
		values[i].Random()
	}

	var pp PublicParams
	startTime := time.Now()
	pp.Paramgen(N)
	duration := time.Since(startTime)
	fmt.Println("parameters are generated in", duration.Microseconds(), "us")

	/*generate commitment*/
	var com Commitment
	startTime = time.Now()
	com.New(pp, values)
	duration = time.Since(startTime)
	fmt.Println("commitment is generated in", duration.Microseconds(), "us")

	/*generate inner proofs and outer proofs*/
	innerProofs := make([]InnerProof, N*N)
	outerProofs := make([]OuterProof, N)

	startTime = time.Now()
	for i := 0; i < outerSize; i++ {
		for j := 0; j < innerSize; j++ {
			innerProofs[i*N+j].NewInnerProof(pp, values[i*N:(i+1)*N], j)
		}
	}
	duration = time.Since(startTime)
	//fmt.Println("All inner proofs are generated in", duration.Nanoseconds(), "ns")
	fmt.Println("Single inner proof is generated in", (duration / time.Duration(outerSize*innerSize)).Microseconds(), "us")

	startTime = time.Now()
	for i := 0; i < outerSize; i++ {
		outerProofs[i].NewOuterProof(pp, values, i)
	}
	duration = time.Since(startTime)
	//fmt.Println("All outer proofs are generated in", duration.Nanoseconds(), "ns")
	fmt.Println("Single outer proof is generated in", (duration / time.Duration(outerSize)).Microseconds(), "us")

	/*single verification*/
	startTime = time.Now()
	for i := 0; i < outerSize; i++ {
		for j := 0; j < innerSize; j++ {
			index := i*N + j
			res := innerProofs[index].VerifySingleInnerProof(pp, com.commit_c1[i], values[index], j)
			if !res {
				fmt.Println("(", i, ",", j, ") inner proof verify res is ", res)
			}
		}
	}
	duration = time.Since(startTime)
	fmt.Println("Single inner proof is verified in", (duration / time.Duration(outerSize*innerSize)).Microseconds(), "us")

	startTime = time.Now()
	for i := 0; i < outerSize; i++ {
		res := outerProofs[i].VerifySingleOuterProof(pp, com.commit_c2, com.commit_c1[i], i)
		if !res {
			fmt.Println("(", i, ") outer proof verify res is ", res)
		}
	}
	duration = time.Since(startTime)
	fmt.Println("Single outer proof is verified in", (duration / time.Duration(outerSize)).Microseconds(), "us")

	/*aggregate proofs*/
	//step 1: prepare the aggregated proofs
	in_set := make([][]int, outerSize)
	in_sub_value := make([][]mcl.Fr, outerSize)
	in_sub_proof := make([][]InnerProof, outerSize)
	out_set := make([]int, outerSize)
	out_sub_value := make([]mcl.G1, outerSize)
	out_sub_proof := make([]OuterProof, outerSize)
	for i := 0; i < outerSize; i++ {
		line_in_set := make([]int, innerSize)
		line_in_sub_value := make([]mcl.Fr, innerSize)
		line_in_sub_proof := make([]InnerProof, innerSize)
		for j := 0; j < innerSize; j++ {
			line_in_set[j] = j
			line_in_sub_value[j] = values[i*N+j]
			line_in_sub_proof[j] = innerProofs[i*N+j]
		}
		in_set[i] = line_in_set
		in_sub_value[i] = line_in_sub_value
		in_sub_proof[i] = line_in_sub_proof

		out_set[i] = i
		out_sub_value[i] = com.commit_c1[i]
		out_sub_proof[i] = outerProofs[i]
	}
	//step2: aggregate proofs
	startTime = time.Now()
	aggInPf := AggregateInnerProof(out_sub_value, in_sub_proof, in_set, in_sub_value, N)
	duration = time.Since(startTime)
	fmt.Println("Aggregate", outerSize*innerSize, "inner proofs takes", duration.Microseconds(), "us")

	startTime = time.Now()
	aggOutPf := AggregateOuterProof(com.commit_c2, out_sub_proof, out_set, out_sub_value, N)
	duration = time.Since(startTime)
	fmt.Println("Aggregate", outerSize, "outer proofs takes", duration.Microseconds(), "us")

	/*batch verification*/
	startTime = time.Now()
	res := aggInPf.BatchVerifyInnerProof(pp, out_sub_value, in_set, in_sub_value)
	if !res {
		fmt.Println("The verification of aggInPf is {}", res)
	}
	duration = time.Since(startTime)
	fmt.Println("Batch verify the aggregated inner proof takes", duration.Microseconds(), "us")

	startTime = time.Now()
	res = aggOutPf.BatchVerifyOuterProof(pp, com.commit_c2, out_set, out_sub_value)
	if !res {
		fmt.Println("The verification of aggOutPf is {}", res)
	}
	duration = time.Since(startTime)
	fmt.Println("Batch verify the aggregated outer proof takes", duration.Microseconds(), "us")

	/*update*/
	//step 1: prepare the delta_value
	changedIndex := make([]int, 2)
	changedIndex[0] = 1
	changedIndex[1] = 1
	var newValue, oldValue mcl.Fr
	newValue.Random()
	oldValue = values[changedIndex[0]*N+changedIndex[1]]
	values[changedIndex[0]*N+changedIndex[1]] = newValue

	multiplier := oldValue
	mcl.FrNeg(&multiplier, &multiplier)
	var deltaValue mcl.Fr
	mcl.FrAdd(&deltaValue, &multiplier, &newValue)

	//step 2: update commit
	startTime = time.Now()
	com.UpdateInnerCommitment(pp, changedIndex, deltaValue)
	duration = time.Since(startTime)
	fmt.Println("Updating inner commitment takes", duration.Microseconds(), "us")

	startTime = time.Now()
	com.UpdateOuterCommitment(pp, changedIndex, deltaValue)
	duration = time.Since(startTime)
	fmt.Println("Updating outer commitment takes", duration.Microseconds(), "us")
	//step 3: update inner proofs in the same line
	startTime = time.Now()
	for j := 0; j < innerSize; j++ {
		updateProofIndex := make([]int, 2)
		updateProofIndex[0] = changedIndex[0]
		updateProofIndex[1] = j
		innerProofs[changedIndex[0]*N+j].UpdateInnerProof(pp, updateProofIndex, changedIndex, deltaValue)
	}
	duration = time.Since(startTime)
	fmt.Println("Updating one inner proof takes", (duration / time.Duration(innerSize)).Microseconds(), "us")
	//step 4: update outer proof
	startTime = time.Now()
	for i := 0; i < outerSize; i++ {
		outerProofs[i].UpdateOuterProof(pp, i, changedIndex, deltaValue)
	}
	duration = time.Since(startTime)
	fmt.Println("Updating one outer proof takes", (duration / time.Duration(outerSize)).Microseconds(), "us")

	/*single verification after updating*/
	//for i := 0; i < N; i++ {
	//	for j := 0; j < N; j++ {
	//		index := i*N + j
	//		res := innerProofs[index].VerifySingleInnerProof(pp, com.commit_c1[i], values[index], j)
	//		if !res {
	//			fmt.Println("(", i, ",", j, ") inner proof verify res is ", res)
	//		}
	//	}
	//	res = outerProofs[i].VerifySingleOuterProof(pp, com.commit_c2, com.commit_c1[i], i)
	//	if !res {
	//		fmt.Println("(", i, ") outer proof verify res is ", res)
	//	}
	//}
}
