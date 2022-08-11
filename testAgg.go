package main

import (
	"fmt"
	"github.com/alinush/go-mcl"
	"time"
)

/*Test Aggregation of square submatrix*/
func testAgg() {
	N := 2048
	outSizes := [10]int{4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048}

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

	/*generate global commitment*/
	var gCom GlobalCommitment
	startTime = time.Now()
	gCom.NewGlocalCommitment(pp, values)
	duration = time.Since(startTime)
	fmt.Println("global commitment is generated in", duration.Microseconds(), "us")

	/*generate local commitments*/
	lComs := make([]LocalCommitment, N)
	startTime = time.Now()
	for i := 0; i < pp.n; i++ {
		lComs[i].NewLocalCommitment(pp, values[i*pp.n:(i+1)*pp.n])
	}
	duration = time.Since(startTime)
	fmt.Println("a local commitment are generated in", (duration / time.Duration(pp.n)).Microseconds(), "us")

	/*generate local proofs and global proofs*/
	localProofs := make([]LocalProof, N*N)
	globalProofs := make([]GlobalProof, N)

	startTime = time.Now()
	for i := 0; i < N; i++ {
		for j := 0; j < N; j++ {
			localProofs[i*N+j].NewLocalProof(pp, values[i*N:(i+1)*N], j)
		}
	}
	duration = time.Since(startTime)
	//fmt.Println("All local proofs are generated in", duration.Nanoseconds(), "ns")
	fmt.Println("Single local proof is generated in", (duration / time.Duration(N*N)).Microseconds(), "us")

	startTime = time.Now()
	for i := 0; i < N; i++ {
		globalProofs[i].NewGlobalProof(pp, values, i)
	}
	duration = time.Since(startTime)
	//fmt.Println("All global proofs are generated in", duration.Nanoseconds(), "ns")
	fmt.Println("Single global proof is generated in", (duration / time.Duration(N)).Microseconds(), "us")

	for _, size := range outSizes {
		globalSize := size
		localSize := size

		fmt.Println(globalSize)
		fmt.Println(localSize)
		/*aggregate proofs*/
		//step 1: prepare the aggregated proofs
		in_set := make([][]int, globalSize)
		in_sub_value := make([][]mcl.Fr, globalSize)
		in_sub_proof := make([][]LocalProof, globalSize)
		out_set := make([]int, globalSize)
		out_sub_value := make([]mcl.G1, globalSize)
		out_sub_proof := make([]GlobalProof, globalSize)
		for i := 0; i < globalSize; i++ {
			line_in_set := make([]int, localSize)
			line_in_sub_value := make([]mcl.Fr, localSize)
			line_in_sub_proof := make([]LocalProof, localSize)
			for j := 0; j < localSize; j++ {
				line_in_set[j] = j
				line_in_sub_value[j] = values[i*N+j]
				line_in_sub_proof[j] = localProofs[i*N+j]
			}
			in_set[i] = line_in_set
			in_sub_value[i] = line_in_sub_value
			in_sub_proof[i] = line_in_sub_proof

			out_set[i] = i
			out_sub_value[i] = lComs[i].local_commitment
			out_sub_proof[i] = globalProofs[i]
		}
		//step2: aggregate proofs
		startTime = time.Now()
		aggLoPf := AggregateLocalProof(out_sub_value, in_sub_proof, in_set, in_sub_value, N)
		duration = time.Since(startTime)
		fmt.Println("Aggregate", globalSize*localSize, "local proofs takes", duration.Microseconds(), "us")

		startTime = time.Now()
		aggGloPf := AggregateGlobalProof(gCom.global_commitment, out_sub_proof, out_set, out_sub_value, N)
		duration = time.Since(startTime)
		fmt.Println("Aggregate", globalSize, "global proofs takes", duration.Microseconds(), "us")

		/*batch verification*/
		startTime = time.Now()
		res := aggLoPf.BatchVerifyLocalProof(pp, out_sub_value, in_set, in_sub_value)
		if !res {
			fmt.Println("The verification of aggLoPf is {}", res)
		}
		duration = time.Since(startTime)
		fmt.Println("Batch verify the aggregated local proof takes", duration.Microseconds(), "us")

		startTime = time.Now()
		res = aggGloPf.BatchVerifyGlobalProof(pp, gCom.global_commitment, out_set, out_sub_value)
		if !res {
			fmt.Println("The verification of aggGloPf is {}", res)
		}
		duration = time.Since(startTime)
		fmt.Println("Batch verify the aggregated global proof takes", duration.Microseconds(), "us")
	}
}
