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
#include "EncryptedArray.h"
#include "FHE.h"

#include "intraSlot.h"
#include "binaryArith.h"
#include "debugging.h"

namespace std {} using namespace std;
static std::vector<zzX> unpackSlotEncoding; // a global variable

// This table provides a set of precomputed "secure parameters.
// TODO: Build utilities so we can generate secure parameters on demand for the
// program at hand.
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

  // Selects the security level. Larger integers require larger security. 
  long prm=1;
  amap.arg("prm", prm, "parameter size (0-tiny,...,7-huge)");

  // Number of bits needed to specify first summand.
  long bitSize1 = 5;
  amap.arg("bitSize1", bitSize1, "bitSize of input integers (<=32)");
  // First summand integer
  long input1 = 0;
  amap.arg("input1", input1, "First input integer. At most bitSize1 bits!");

  // Number of bits needed to specify second summand.
  long bitSize2 = 0;
  amap.arg("bitSize2", bitSize2, "bitSize of 2nd input integer (<=32)",
           "same as bitSize");
  // Second summand integer
  long input2 = 0;
  amap.arg("input2", input2, "First input integer. At most bitSize2 bits!");

  // Size of the sum in bits.
  long outSize = 0;
  amap.arg("outSize", outSize, "bitSize of output integers", "as many as needed");

  // Random seed used in scheme.
  long seed=0;
  amap.arg("seed", seed, "PRG seed");

  amap.parse(argc, argv);

  assert(prm >= 0 && prm < 5);
  SetSeed(ZZ(seed));

  if (bitSize1<=0) bitSize1=5;
  else if (bitSize1>32) bitSize1=32;
  if (bitSize2<=0) bitSize2=bitSize1;
  else if (bitSize2>32) bitSize2=32;

  // Check that inputs are can fir within specified bits.
  assert(input1 < pow(2, bitSize1));
  assert(input2 < pow(2, bitSize2));
  cout << "Checked that inputs fit within the specified number of bits." <<
    endl;


  long* vals = mValues[prm];
  long p = vals[0];
  //  long phim = vals[1];
  long cyclotomic_degree = vals[2];

  // TODO:I'm not entirely sure what mvec is. I think it's the explicit
  // parameters that specify the cyclotomic polynomial of that degree, but not
  // sure.
  NTL::Vec<long> mvec;
  append(mvec, vals[4]);
  if (vals[5]>1) append(mvec, vals[5]);
  if (vals[6]>1) append(mvec, vals[6]);

  std::vector<long> generators;
  generators.push_back(vals[7]);
  if (vals[8]>1) generators.push_back(vals[8]);
  if (vals[9]>1) generators.push_back(vals[9]);

  std::vector<long> orders;
  orders.push_back(vals[10]);
  if (abs(vals[11])>1) orders.push_back(vals[11]);
  if (abs(vals[12])>1) orders.push_back(vals[12]);

  long bits_per_level = vals[13];
  long c = vals[14];

  // Compute the number of levels
  long num_levels;
  double nBits =
    (outSize>0 && outSize<2*bitSize1)? outSize : (2*bitSize1);
  double add2NumsLvls = log(nBits) / log(2.0);
  num_levels = 3 + add2NumsLvls;


  cout <<"input bitSizes="<<bitSize1<<','<<bitSize2
        <<", output size bound="<<outSize;
  cout << "computing key-independent tables..." << std::flush;

  // Hamming weight of secret key
  long w = 64; 


  // FHEcontext is a convenient book-keeping class that
  // stores a variety of parameters tied to the fully
  // homomorphic encryption scheme.
  FHEcontext context(cyclotomic_degree, p, /*r=*/1, generators, orders);
  context.bitsPerLevel = bits_per_level;
  buildModChain(context, num_levels, c,/*extraBits=*/8);
  context.makeBootstrappable(mvec, /*t=*/0,
                              /*flag=*/false, /*cacheType=DCRT*/2);
  buildUnpackSlotEncoding(unpackSlotEncoding, *context.ea);

  
  cout << " done.\n";
  context.zMStar.printout();
  cout << " num_levels="<<num_levels<<", bits_per_level="<<bits_per_level<<endl;
  cout << "\ncomputing key-dependent tables..." << std::flush;

  // Print some information about the security level of the
  // current scheme.
  std::cout << "security=" << context.securityLevel()<<endl;

  // Stores the secret key. Almost like the FHEPubKey object, 
  FHESecKey secKey(context);
  secKey.GenSecKey(/*Hweight=*/128);
  addSome1DMatrices(secKey); // compute key-switching matrices
  addFrbMatrices(secKey);
  cout << " done\n";

  activeContext = &context; // make things a little easier sometimes

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
  }
  resize(encb, bitSize2, Ctxt(secKey));
  for (long i=0; i<bitSize2; i++) {
    secKey.Encrypt(encb[i], ZZX((pb>>i)&1));
  }

  cout << "\n  bits-size "<<bitSize1<<'+'<<bitSize2;
  if (outSize>0) cout << "->"<<outSize;
  cout <<endl;
  CheckCtxt(encb[0], "b4 addition");

  // Test addition
  vector<long> slots;
  CtPtrs_VecCt eep(eSum);  // A wrapper around the output vector
  addTwoNumbers(eep, CtPtrs_VecCt(enca), CtPtrs_VecCt(encb),
                outSize, &unpackSlotEncoding);
  decryptBinaryNums(slots, eep, secKey, ea);
  // get rid of the wrapper
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

  cout << "  *** testAdd PASS ***\n";
}
