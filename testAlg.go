package main

import (
	"fmt"
	"github.com/alinush/go-mcl"
	"time"
)

/*Test all algorithms*/
func testAlg() {
	N := 2048

	//maxAggSize := 1024
	//aggSizes := [1]int{1024}

	maxAggSize := 2048
	aggSizes := [10]int{4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048}
	fmt.Println("N=", N)

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

	/*generate individual proof(global proof+local commitment+local proof)*/
	rIndProof := make([]IndividualProof, maxAggSize)
	rowIndex := 0
	cIndProof := make([]IndividualProof, maxAggSize)
	columnIndex := 0
	startTime = time.Now()
	for i := 0; i < maxAggSize; i++ {
		rIndProof[i].global_proof.NewGlobalProof(pp, values, rowIndex)
		rIndProof[i].local_commitment.NewLocalCommitment(pp, values[rowIndex*pp.n:(rowIndex+1)*pp.n])
		rIndProof[i].local_proof.NewLocalProof(pp, values[rowIndex*N:(rowIndex+1)*N], i)

		cIndProof[i].global_proof.NewGlobalProof(pp, values, i)
		cIndProof[i].local_commitment.NewLocalCommitment(pp, values[i*pp.n:(i+1)*pp.n])
		cIndProof[i].local_proof.NewLocalProof(pp, values[i*N:(i+1)*N], columnIndex)
	}
	duration = time.Since(startTime)
	fmt.Println("an individual proof is generated in", (duration / time.Duration(maxAggSize*2)).Microseconds(), "us")

	/*single verification*/
	startTime = time.Now()
	for i := 0; i < maxAggSize; i++ {
		//verify global proof
		res := rIndProof[i].global_proof.VerifySingleGlobalProof(pp, gCom.global_commitment, rIndProof[i].local_commitment.local_commitment, rowIndex)
		if !res {
			fmt.Println("(", rowIndex, ",", i, ") global proof verify res is ", res)
		}
		//verify local proof
		res = rIndProof[i].local_proof.VerifySingleLocalProof(pp, rIndProof[i].local_commitment.local_commitment, values[rowIndex*N+i], i)
		if !res {
			fmt.Println("(", rowIndex, ",", i, ") local proof verify res is ", res)
		}

		//verify global proof
		res = cIndProof[i].global_proof.VerifySingleGlobalProof(pp, gCom.global_commitment, cIndProof[i].local_commitment.local_commitment, i)
		if !res {
			fmt.Println("(", i, ",", columnIndex, ") global proof verify res is ", res)
		}
		//verify local proof
		res = cIndProof[i].local_proof.VerifySingleLocalProof(pp, cIndProof[i].local_commitment.local_commitment, values[i*N+columnIndex], columnIndex)
		if !res {
			fmt.Println("(", i, ",", columnIndex, ") local proof verify res is ", res)
		}
	}
	duration = time.Since(startTime)
	fmt.Println("An individual proof is verified in", (duration / time.Duration(2*maxAggSize)).Microseconds(), "us")

	/*aggregation and verification*/
	rowSize := 1
	columnSize := 1
	for _, size := range aggSizes {
		fmt.Println("size:", size)
		/*aggregate proofs and verification of aggregated proof(best case)*/
		//step 1: prepare the aggregated proofs
		in_set := make([][]int, rowSize)
		in_sub_value := make([][]mcl.Fr, rowSize)
		in_sub_proof := make([][]LocalProof, rowSize)
		out_set := make([]int, rowSize)
		out_sub_value := make([]mcl.G1, rowSize)
		out_sub_proof := make([]GlobalProof, rowSize)
		for i := 0; i < rowSize; i++ {
			line_in_set := make([]int, size)
			line_in_sub_value := make([]mcl.Fr, size)
			line_in_sub_proof := make([]LocalProof, size)
			for j := 0; j < size; j++ {
				line_in_set[j] = j
				line_in_sub_value[j] = values[i*N+j]
				line_in_sub_proof[j] = rIndProof[j].local_proof
			}
			in_set[i] = line_in_set
			in_sub_value[i] = line_in_sub_value
			in_sub_proof[i] = line_in_sub_proof

			out_set[i] = i
			out_sub_value[i] = rIndProof[0].local_commitment.local_commitment
			out_sub_proof[i] = rIndProof[0].global_proof
		}
		//step2: aggregate proofs
		startTime = time.Now()
		aggLoPf := AggregateLocalProof(out_sub_value, in_sub_proof, in_set, in_sub_value, N)
		aggGloPf := AggregateGlobalProof(gCom.global_commitment, out_sub_proof, out_set, out_sub_value, N)
		duration = time.Since(startTime)
		fmt.Println("BEST CASE-Aggregate", size, "individual proofs takes", duration.Microseconds(), "us")

		//batch verification
		startTime = time.Now()
		res := aggGloPf.BatchVerifyGlobalProof(pp, gCom.global_commitment, out_set, out_sub_value)
		if !res {
			fmt.Println("The verification of aggGloPf is {}", res)
		}
		res = aggLoPf.BatchVerifyLocalProof(pp, out_sub_value, in_set, in_sub_value)
		if !res {
			fmt.Println("The verification of aggLoPf is {}", res)
		}
		duration = time.Since(startTime)
		fmt.Println("BEST CASE-Batch verify the aggregated proof takes", duration.Microseconds(), "us")

		/*aggregate proofs and verification of aggregated proof(worst case)*/
		//step 1: prepare the aggregated proofs
		in_set = make([][]int, size)
		in_sub_value = make([][]mcl.Fr, size)
		in_sub_proof = make([][]LocalProof, size)
		out_set = make([]int, size)
		out_sub_value = make([]mcl.G1, size)
		out_sub_proof = make([]GlobalProof, size)
		for i := 0; i < size; i++ {
			line_in_set := make([]int, columnSize)
			line_in_sub_value := make([]mcl.Fr, columnSize)
			line_in_sub_proof := make([]LocalProof, columnSize)
			for j := 0; j < columnSize; j++ {
				line_in_set[j] = j
				line_in_sub_value[j] = values[i*N+j]
				line_in_sub_proof[j] = cIndProof[i].local_proof
			}
			in_set[i] = line_in_set
			in_sub_value[i] = line_in_sub_value
			in_sub_proof[i] = line_in_sub_proof

			out_set[i] = i
			out_sub_value[i] = cIndProof[i].local_commitment.local_commitment
			out_sub_proof[i] = cIndProof[i].global_proof
		}
		//step2: aggregate proofs
		startTime = time.Now()
		aggLoPf = AggregateLocalProof(out_sub_value, in_sub_proof, in_set, in_sub_value, N)
		aggGloPf = AggregateGlobalProof(gCom.global_commitment, out_sub_proof, out_set, out_sub_value, N)
		duration = time.Since(startTime)
		fmt.Println("WORST CASE-Aggregate", size, "individual proofs takes", duration.Microseconds(), "us")

		//batch verification
		startTime = time.Now()
		res = aggGloPf.BatchVerifyGlobalProof(pp, gCom.global_commitment, out_set, out_sub_value)
		if !res {
			fmt.Println("The verification of aggGloPf is {}", res)
		}
		res = aggLoPf.BatchVerifyLocalProof(pp, out_sub_value, in_set, in_sub_value)
		if !res {
			fmt.Println("The verification of aggLoPf is {}", res)
		}
		duration = time.Since(startTime)
		fmt.Println("WORST CASE-Batch verify the aggregated proof takes", duration.Microseconds(), "us")
	}

	/*update*/
	//step 1: prepare the delta_value
	changedIndex := make([]int, 2)
	changedIndex[0] = 1
	changedIndex[0] = 1
	var newValue, oldValue mcl.Fr
	newValue.Random()
	oldValue = values[changedIndex[0]*N+changedIndex[1]]
	values[changedIndex[0]*N+changedIndex[1]] = newValue

	multiplier := oldValue
	mcl.FrNeg(&multiplier, &multiplier)
	var deltaValue mcl.Fr
	mcl.FrAdd(&deltaValue, &multiplier, &newValue)

	//step 2: update global commitment
	startTime = time.Now()
	gCom.UpdateGlobalCommitment(pp, changedIndex, deltaValue)
	duration = time.Since(startTime)
	fmt.Println("Updating global commitment takes", duration.Microseconds(), "us")

	//step 3: update individual proofs in rIndProof
	startTime = time.Now()
	for i := 0; i < maxAggSize; i++ {
		rIndProof[i].local_commitment.UpdateLocalCommitment(pp, changedIndex, deltaValue)
		updateProofIndex := make([]int, 2)
		updateProofIndex[0] = changedIndex[0]
		updateProofIndex[1] = i
		rIndProof[i].local_proof.UpdateLocalProof(pp, updateProofIndex, changedIndex, deltaValue)
	}
	duration = time.Since(startTime)
	fmt.Println("WORST CASE-Updating an individual proof (=updating local commitment and local proof) takes", (duration / time.Duration(maxAggSize)).Microseconds(), "us")
}

//func udpateAll() {
//	//n := 1024
//
//	var deltaValue mcl.Fr
//	deltaValue.Random()
//
//	var proof mcl.G1
//	proof.Random()
//	var res_c1 mcl.G1
//	res_c1.Random()
//	var res_c2 mcl.G1
//
//	//var g2r mcl.G2
//	//g2r.Random()
//	//var g2 mcl.G2
//
//	//for i := 0; i < 10; i++ {
//	//	for i := 0; i < n; i++ {
//	//		mcl.G1Mul(&res_c2, &res_c1, &deltaValue)
//	//		mcl.G1Add(&proof, &proof, &res_c2)
//	//	}
//	//}
//
//	//bases := make([]mcl.G2, n)
//	//ti := make([]mcl.Fr, n)
//	//for i := 0; i < n; i++ {
//	//	bases[i].Random()
//	//	ti[i].Random()
//	//}
//	//var res mcl.G2
//	//res.Random()
//	//var rhs mcl.GT
//	var lhs mcl.GT
//	lhs.SetString("1", 10)
//
//	log := (2048 * 2 * 2 * 2) * (2048 * 2 * 2 * 2)
//	//ps := make([]mcl.G1, log+1)
//	//qs := make([]mcl.G2, log+1)
//	//for j := 0; j < log+1; j++ {
//	//	ps[j].Random()
//	//	qs[j].Random()
//	//}
//	startTime := time.Now()
//	for i := 0; i < 1; i++ {
//
//		//mcl.G1Mul(&res_c2, &res_c1, &deltaValue)
//		//mcl.G2Mul(&g2, &g2r, &deltaValue)
//		//mcl.MillerLoopVec(&rhs, ps, qs)
//		//lhs.IsEqual(&rhs)
//		for j := 0; j < log; j++ {
//			mcl.G1Mul(&res_c2, &res_c1, &deltaValue)
//			mcl.G1Add(&proof, &proof, &res_c2)
//		}
//		////mcl.G2MulVec(&res, bases, ti)
//		//mcl.MillerLoopVec(&rhs, ps, qs)
//	}
//	duration := time.Since(startTime)
//	fmt.Println("Updating all proofs takes", duration.Microseconds()/1, "us")
//}
