/* A simple program that demonstrates a simple homomorphic program on 4 input values.
 * */

#include <iostream>
#include <NTL/ZZ.h>
#include "FHE.h"
#include "timing.h"
#include <NTL/lzz_pXFactoring.h>

#include <cassert>
#include <cstdio>

#include <fstream>
#include <vector>
#include <cmath>
#include <algorithm>
#include <NTL/BasicThreadPool.h>
NTL_CLIENT

#include "EncryptedArray.h"
#include "FHE.h"

#include "intraSlot.h"
#include "binaryArith.h"
#define DEBUG_PRINTOUT 1

#ifdef DEBUG_PRINTOUT
#include "debugging.h"
#endif

namespace std {} using namespace std;
static std::vector<zzX> unpackSlotEncoding; // a global variable
static bool verbose=false;
static long mValues[][15] = { 
// { p, phi(m),   m,   d, m1, m2, m3,    g1,   g2,   g3, ord1,ord2,ord3, B,c}
  {  2,    48,   105, 12,   3, 35,  0,    71,    76,    0,   2,  2,   0, 25, 2},
  {  2 ,  600,  1023, 10,  11, 93,  0,   838,   584,    0,  10,  6,   0, 25, 2},
  {  2,  2304,  4641, 24,   7,  3,221,  3979,  3095, 3760,   6,  2,  -8, 25, 3},
  {  2,  5460,  8193, 26,8193,  0,  0,    46,     0,    0, 210,  0,   0, 25, 3},
  {  2,  8190,  8191, 13,8191,  0,  0,    39,     0,    0, 630,  0,   0, 25, 3},
  {  2, 10752, 11441, 48,  17,673,  0,  4712,  2024,    0,  16,-14,   0, 25, 3},
  {  2, 15004, 15709, 22,  23,683,  0,  4099, 13663,    0,  22, 31,   0, 25, 3},
  {  2, 27000, 32767, 15,  31,  7,151, 11628, 28087,25824,  30,  6, -10, 28, 4}
};

void testAdd(FHESecKey& secKey, long bitSize1, long bitSize2,
             long outSize, bool bootstrap)
{
  const EncryptedArray& ea = *(secKey.getContext().ea);
  long mask = (outSize? ((1L<<outSize)-1) : -1);

  // Choose two random n-bit integers
  long pa = RandomBits_long(bitSize1);
  long pb = RandomBits_long(bitSize2);

  // Encrypt the individual bits
  NTL::Vec<Ctxt> eSum, enca, encb;

  resize(enca, bitSize1, Ctxt(secKey));
  for (long i=0; i<bitSize1; i++) {
    secKey.Encrypt(enca[i], ZZX((pa>>i)&1));
    if (bootstrap) { // put them at a lower level
      enca[i].modDownToLevel(5);
    }
  }
  resize(encb, bitSize2, Ctxt(secKey));
  for (long i=0; i<bitSize2; i++) {
    secKey.Encrypt(encb[i], ZZX((pb>>i)&1));
    if (bootstrap) { // put them at a lower level
      encb[i].modDownToLevel(5);
    }
  }
  if (verbose) {
    cout << "\n  bits-size "<<bitSize1<<'+'<<bitSize2;
    if (outSize>0) cout << "->"<<outSize;
    cout <<endl;
    CheckCtxt(encb[0], "b4 addition");
  }

  // Test addition
  vector<long> slots;
  {CtPtrs_VecCt eep(eSum);  // A wrapper around the output vector
  addTwoNumbers(eep, CtPtrs_VecCt(enca), CtPtrs_VecCt(encb),
                outSize, &unpackSlotEncoding);
  decryptBinaryNums(slots, eep, secKey, ea);
  } // get rid of the wrapper
  if (verbose) CheckCtxt(eSum[lsize(eSum)-1], "after addition");
  long pSum = pa+pb;
  if (slots[0] != ((pa+pb)&mask)) {
    cout << "addTwoNums error: pa="<<pa<<", pb="<<pb
         << ", but pSum="<<slots[0]
         << " (should be ="<<(pSum&mask)<<")\n";
    exit(0);
  }
  else if (verbose) {
    cout << "addTwoNums succeeded: ";
    if (outSize) cout << "bottom "<<outSize<<" bits of ";
    cout << pa<<"+"<<pb<<"="<<slots[0]<<endl;
  }

#ifdef DEBUG_PRINTOUT
  const Ctxt* minCtxt = nullptr;
  long minLvl=1000;
  for (const Ctxt& c: eSum) {
    long lvl = c.findBaseLevel();
    if (lvl < minLvl) {
      minCtxt = &c;
      minLvl = lvl;
    }
  }
  decryptAndPrint((cout<<" after addition: "), *minCtxt, secKey, ea,0);
  cout << endl;
#endif
}


int main(int argc, char *argv[])
{
  ArgMapping amap;

  // TODO: What does this do?
  long prm=1;
  amap.arg("prm", prm, "parameter size (0-tiny,...,7-huge)");

  long bitSize = 5;
  amap.arg("bitSize", bitSize, "bitSize of input integers (<=32)");
  long bitSize2 = 0;
  amap.arg("bitSize2", bitSize2, "bitSize of 2nd input integer (<=32)",
           "same as bitSize");
  long outSize = 0;
  amap.arg("outSize", outSize, "bitSize of output integers", "as many as needed");

  // Technical parameter. Use if you want to explicitly set generator elements
  // for the plaintext arrays.
  //Vec<long> gens;
  //amap.arg("gens", gens, "use specified vector of generators", NULL);
  //amap.note("e.g., gens='[562 1871 751]'");

  // Technical parameter. The order of each generator specified in ords.
  //Vec<long> ords;
  //amap.arg("ords", ords, "use specified vector of orders", NULL);
  //amap.note("e.g., ords='[4 2 -4]', negative means 'bad'");

  long nTests = 2;
  amap.arg("nTests", nTests, "number of tests to run");

  bool bootstrap = false;
  amap.arg("bootstrap", bootstrap, "test multiplication with bootstrapping");

  // Random seed used in scheme.
  long seed=0;
  amap.arg("seed", seed, "PRG seed");

  // The number of rounds of encrypted computation. If R > 1, then we need to
  // "bootstrap" between rounds which adds a heavy computational overhead.
  long R=1;
  amap.arg("R", R, "number of rounds");

  //// If p=2, then plaintext entries are bits.
  //long p=2;
  //amap.arg("p", p, "plaintext base");

  // Technical parameter. In case r=1, then plaintext entries are just bits.
  long r=1;
  amap.arg("r", r,  "lifting");

  long d=1;
  amap.arg("d", d, "degree of the field extension");

  // Key-switching is an operation which swaps out the key under which a
  // particular ciphertext is encoded. Key-switching is used in a variety of
  // places in homomorphic encryption, notably during "relinearization" which
  // happens after homomorphic multiplication of ciphertexts. The key-switching
  // matrix is a 2xn matrix, where n is some number < L (see description of L
  // below).
  //long c=2;
  //amap.arg("c", c, "number of columns in the key-switching matrices");

  // The number of "bits" of security the scheme provides (see
  // https://en.wikipedia.org/wiki/Security_level). Basic idea is that for a
  // security level of 80, the attacker needs to perform ~2^80 operations to
  // break the scheme.
  long k=80;
  amap.arg("k", k, "security parameter");

  // The number of levels in the modulus chain. See detailed comment below.
  //long L=0;
  //amap.arg("L", L, "# of levels in the modulus chain",  "heuristic");

  long s=0;
  amap.arg("s", s, "minimum number of slots");

  // See comment about cyclotomic polynomials below. If chosen_m is set, this
  // value is passed to helper findM that checks if it is secure.
  long chosen_m=0;
  amap.arg("m", chosen_m, "use specified value for cyclotomic polynomial.", NULL);

  amap.parse(argc, argv);

  assert(prm >= 0 && prm < 5);

  SetSeed(ZZ(seed));

  if (bitSize<=0) bitSize=5;
  else if (bitSize>32) bitSize=32;
  if (bitSize2<=0) bitSize2=bitSize;
  else if (bitSize2>32) bitSize2=32;

  long* vals = mValues[prm];
  long p = vals[0];
  //  long phim = vals[1];
  long m = vals[2];

  NTL::Vec<long> mvec;
  append(mvec, vals[4]);
  if (vals[5]>1) append(mvec, vals[5]);
  if (vals[6]>1) append(mvec, vals[6]);

  std::vector<long> gens;
  gens.push_back(vals[7]);
  if (vals[8]>1) gens.push_back(vals[8]);
  if (vals[9]>1) gens.push_back(vals[9]);

  std::vector<long> ords;
  ords.push_back(vals[10]);
  if (abs(vals[11])>1) ords.push_back(vals[11]);
  if (abs(vals[12])>1) ords.push_back(vals[12]);


  // L is the number of "levels" to the FHE scheme. The number of levels
  // governs how many compute operations can be performed on encrypted data
  // before the encryption needs to be refreshed (this refreshing process is
  // called "bootstrapping"). 
  // See comment below about the modulus chain. 
  //if (L==0) { // determine L based on R,r
  //  L = 3*R+3;
  //  if (p>2 || r>1) { // add some more primes for each round
  //    long addPerRound = 2*ceil(log((double)p)*r*3)/(log(2.0)*FHE_p2Size) +1;
  //    L += R * addPerRound;
  //  }
  //}

  //cout << "*** L: " << L << endl;
  long B = vals[13];
  long c = vals[14];

  // Compute the number of levels
  long L;
  if (bootstrap) L=30; // that should be enough
  else {
    double nBits =
      (outSize>0 && outSize<2*bitSize)? outSize : (2*bitSize);
    double three4twoLvls = log(nBits/2) / log(1.5);
    double add2NumsLvls = log(nBits) / log(2.0);
    L = 3 + ceil(three4twoLvls + add2NumsLvls);
  }

  cout <<"input bitSizes="<<bitSize<<','<<bitSize2
        <<", output size bound="<<outSize
        <<", running "<<nTests<<" tests for each function\n";
  cout << "computing key-independent tables..." << std::flush;

  // Hamming weight of secret key
  long w = 64; 

  // The FHE scheme uses a technical parameter called a cyclotomic polynomial.
  // These polynomials are indexed by whole numbers m. The helper findM helps
  // select a value of m that meets our security requirements.
  //long m = FindM(k, L, c, p, d, s, chosen_m, false);

  // Converting gens and ords into vector<long> types.
  //vector<long> gens1, ords1;
  //convert(gens1, gens);
  //convert(ords1, ords);

  // FHEcontext is a convenient book-keeping class that stores a variety of
  // parameters tied to the fully homomorphic encryption scheme.
  //FHEcontext context(m, p, r, gens1, ords1);
  FHEcontext context(m, p, /*r=*/1, gens, ords);
  context.bitsPerLevel = B;
  buildModChain(context, L, c,/*extraBits=*/8);
  if (bootstrap) {
    context.makeBootstrappable(mvec, /*t=*/0,
                               /*flag=*/false, /*cacheType=DCRT*/2);
  }
  buildUnpackSlotEncoding(unpackSlotEncoding, *context.ea);

  
  cout << " done.\n";
  context.zMStar.printout();
  cout << " L="<<L<<", B="<<B<<endl;
  cout << "\ncomputing key-dependent tables..." << std::flush;
  // FHE schemes use a sequence of parameters called the modulus chain. These
  // "moduli" are ordered in size, q_0 < q_1 < --- < q_L. At the start of
  // encryption, the largest modulus q_L is used. For technical reasons, as
  // encryption proceeds, have to swap down to smaller and smaller moduli. When
  // q_0 is reached, the FHE scheme can no longer compute on the encrypted
  // data. At this point, a "bootstrapping" step is needed (not used in this
  // file) to refresh.
  //buildModChain(context, L, c);

  // G is a technical parameter used to define the plaintexts. Formally, an
  // irreducible polynomial.
  //ZZX G;
  //G = makeIrredPoly(p, d); 

  //context.zMStar.printout();
  //std::cout << endl;

  // Print some information about the security level of the current scheme.
  std::cout << "security=" << context.securityLevel()<<endl;

  // Stores the secret key. Almost like the FHEPubKey object, 
  //FHESecKey secretKey(context);
  FHESecKey secKey(context);
  secKey.GenSecKey(/*Hweight=*/128);
  addSome1DMatrices(secKey); // compute key-switching matrices
  addFrbMatrices(secKey);
  if (bootstrap) secKey.genRecryptData();
  if (verbose) cout << " done\n";

  activeContext = &context; // make things a little easier sometimes

  testAdd(secKey, bitSize, bitSize2, outSize, bootstrap);
  cout << "  *** testAdd PASS ***\n";


}
