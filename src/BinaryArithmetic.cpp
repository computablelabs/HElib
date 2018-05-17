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

int main(int argc, char *argv[])
{
  ArgMapping amap;

  // TODO: What does this do?
  long prm=1;
  amap.arg("prm", prm, "parameter size (0-tiny,...,7-huge)");

  long bitSize1 = 5;
  amap.arg("bitSize1", bitSize1, "bitSize of input integers (<=32)");
  long input1 = 0;
  amap.arg("input1", input1, "First input integer. At most bitSize1 bits!");

  long bitSize2 = 0;
  amap.arg("bitSize2", bitSize2, "bitSize of 2nd input integer (<=32)",
           "same as bitSize");
  long input2 = 0;
  amap.arg("input2", input2, "First input integer. At most bitSize2 bits!");

  long outSize = 0;
  amap.arg("outSize", outSize, "bitSize of output integers", "as many as needed");


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

  // Technical parameter. In case r=1, then plaintext entries are just bits.
  long r=1;
  amap.arg("r", r,  "lifting");

  long d=1;
  amap.arg("d", d, "degree of the field extension");

  // The number of "bits" of security the scheme provides (see
  // https://en.wikipedia.org/wiki/Security_level). Basic idea is that for a
  // security level of 80, the attacker needs to perform ~2^80 operations to
  // break the scheme.
  long k=80;
  amap.arg("k", k, "security parameter");

  long s=0;
  amap.arg("s", s, "minimum number of slots");

  amap.parse(argc, argv);

  assert(prm >= 0 && prm < 5);

  SetSeed(ZZ(seed));

  if (bitSize1<=0) bitSize1=5;
  else if (bitSize1>32) bitSize1=32;
  if (bitSize2<=0) bitSize2=bitSize1;
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

  long B = vals[13];
  long c = vals[14];

  // Compute the number of levels
  long L;
  if (bootstrap) L=30; // that should be enough
  else {
    double nBits =
      (outSize>0 && outSize<2*bitSize1)? outSize : (2*bitSize1);
    double three4twoLvls = log(nBits/2) / log(1.5);
    double add2NumsLvls = log(nBits) / log(2.0);
    L = 3 + ceil(three4twoLvls + add2NumsLvls);
  }

  cout <<"input bitSizes="<<bitSize1<<','<<bitSize2
        <<", output size bound="<<outSize
        <<", running "<<nTests<<" tests for each function\n";
  cout << "computing key-independent tables..." << std::flush;

  // Hamming weight of secret key
  long w = 64; 


  // FHEcontext is a convenient book-keeping class that
  // stores a variety of parameters tied to the fully
  // homomorphic encryption scheme.
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

  // Print some information about the security level of the current scheme.
  std::cout << "security=" << context.securityLevel()<<endl;

  // Stores the secret key. Almost like the FHEPubKey object, 
  FHESecKey secKey(context);
  secKey.GenSecKey(/*Hweight=*/128);
  addSome1DMatrices(secKey); // compute key-switching matrices
  addFrbMatrices(secKey);
  if (bootstrap) secKey.genRecryptData();
  if (verbose) cout << " done\n";

  activeContext = &context; // make things a little easier sometimes

  //testAdd(secKey, bitSize1, bitSize2, outSize, bootstrap);
  const EncryptedArray& ea = *(secKey.getContext().ea);
  long mask = (outSize? ((1L<<outSize)-1) : -1);

  // Choose two random n-bit integers
  //long pa = RandomBits_long(bitSize1);
  long pa = input1;
  cout << "First integer pa: " << pa << endl;
  //long pb = RandomBits_long(bitSize2);
  long pb = input2;
  cout << "Second integer pb: " << pb << endl;

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

  cout << "\n  bits-size "<<bitSize1<<'+'<<bitSize2;
  if (outSize>0) cout << "->"<<outSize;
  cout <<endl;
  CheckCtxt(encb[0], "b4 addition");

  // Test addition
  vector<long> slots;
  {CtPtrs_VecCt eep(eSum);  // A wrapper around the output vector
  addTwoNumbers(eep, CtPtrs_VecCt(enca), CtPtrs_VecCt(encb),
                outSize, &unpackSlotEncoding);
  decryptBinaryNums(slots, eep, secKey, ea);
  } // get rid of the wrapper
  CheckCtxt(eSum[lsize(eSum)-1], "after addition");
  long pSum = pa+pb;
  if (slots[0] != ((pa+pb)&mask)) {
    cout << "addTwoNums error: pa="<<pa<<", pb="<<pb
         << ", but pSum="<<slots[0]
         << " (should be ="<<(pSum&mask)<<")\n";
    exit(0);
  }
  cout << "addTwoNums succeeded: ";
  if (outSize) cout << "bottom "<<outSize<<" bits of ";
  cout << pa<<"+"<<pb<<"="<<slots[0]<<endl;

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
  cout << "  *** testAdd PASS ***\n";


}
