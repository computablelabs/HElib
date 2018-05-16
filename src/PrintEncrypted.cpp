/* A very simple program that encrypts a string and prints
 * out its encrypted form
 */

#include <iostream>
#include <NTL/ZZ.h>
#include <NTL/BasicThreadPool.h>
#include "FHE.h"
#include "timing.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>

#include <cassert>
#include <cstdio>

#ifdef DEBUG_PRINTOUT
#define debugCompare(ea,sk,p,c) {\
  NewPlaintextArray pp(ea);\
  ea.decrypt(c, sk, pp);\
  if (!equals(ea, pp, p)) { \
    std::cout << "oops:\n"; std::cout << p << "\n"; \
    std::cout << pp << "\n"; \
    exit(0); \
  }}
#else
#define debugCompare(ea,sk,p,c)
#endif


namespace std {} using namespace std;

int main(int argc, char *argv[])
{
  char buffer[32];
  ArgMapping amap;

  Vec<long> input;
  amap.arg("input", input, "Vector of numbers to encode", NULL);
  amap.note("e.g., input='[500 1870 750]'");

  Vec<long> gens;
  amap.arg("gens", gens, "use specified vector of generators", NULL);
  amap.note("e.g., gens='[562 1871 751]'");

  Vec<long> ords;
  amap.arg("ords", ords, "use specified vector of orders", NULL);
  amap.note("e.g., ords='[4 2 -4]', negative means 'bad'");


  long seed=0;
  amap.arg("seed", seed, "PRG seed");

  long R=1;
  amap.arg("R", R, "number of rounds");

  long p=2;
  amap.arg("p", p, "plaintext base");

  long r=1;
  amap.arg("r", r,  "lifting");

  long d=1;
  amap.arg("d", d, "degree of the field extension");
  amap.note("d == 0 => factors[0] defines extension");

  long c=2;
  amap.arg("c", c, "number of columns in the key-switching matrices");

  long k=80;
  amap.arg("k", k, "security parameter");

  long L=0;
  amap.arg("L", L, "# of levels in the modulus chain",  "heuristic");

  long s=0;
  amap.arg("s", s, "minimum number of slots");

  long chosen_m=0;
  amap.arg("m", chosen_m, "use specified value as modulus", NULL);

  amap.parse(argc, argv);

  cout << "*** input: " << input << endl;

  SetSeed(ZZ(seed));

  if (L==0) { // determine L based on R,r
    L = 3*R+3;
    if (p>2 || r>1) { // add some more primes for each round
      long addPerRound = 2*ceil(log((double)p)*r*3)/(log(2.0)*FHE_p2Size) +1;
      L += R * addPerRound;
    }
  }

  cout << "*** L: " << L << endl;

  long w = 64; // Hamming weight of secret key
  //  long L = z*R; // number of levels


  cout << "*** Hello World!"
      << endl;

  long m = FindM(k, L, c, p, d, s, chosen_m, true);

  // I don't understand what these lines do.
  vector<long> gens1, ords1;
  convert(gens1, gens);
  convert(ords1, ords);

  FHEcontext context(m, p, r, gens1, ords1);
  buildModChain(context, L, c);

  ZZX G;
  if (d == 0)
    G = context.alMod.getFactorsOverZZ()[0];
  else
    G = makeIrredPoly(p, d); 

  context.zMStar.printout();
  std::cout << endl;

  std::cout << "security=" << context.securityLevel()<<endl;
  std::cout << "# ctxt primes = " << context.ctxtPrimes.card() << "\n";
  std::cout << "# bits in ctxt primes = " 
  << long(context.logOfProduct(context.ctxtPrimes)/log(2.0) + 0.5) << "\n";
  std::cout << "# special primes = " << context.specialPrimes.card() << "\n";
  std::cout << "# bits in special primes = " 
  << long(context.logOfProduct(context.specialPrimes)/log(2.0) + 0.5) << "\n";
  std::cout << "G = " << G << "\n";

  FHESecKey secretKey(context);
  const FHEPubKey& publicKey = secretKey;
  secretKey.GenSecKey(w); // A Hamming-weight-w secret key
  addSome1DMatrices(secretKey); // compute key-switching matrices that we need

  EncryptedArray ea(context, G);
  long nslots = ea.size();
  std::cout << "nslot = " << nslots << endl;

  NewPlaintextArray p0(ea);
  NewPlaintextArray p1(ea);
  NewPlaintextArray p2(ea);
  NewPlaintextArray p3(ea);

  //random(ea, p0);
  random(ea, p1);
  random(ea, p2);
  random(ea, p3);

  Ctxt c0(publicKey), c1(publicKey), c2(publicKey), c3(publicKey);

  vector<ZZX> ptxts[1];
  ZZX ptxt;
  ptxt.SetLength(3);
  ptxt[0] = 1;
  ptxt[1] = 2;
  ptxt[2] = 3;
  std::cout << "ptxt: " << ptxt << endl;
  std::cout << "ptxt[0]: " << ptxt[0] << endl;
  //ptxts[0] = ptxt;
  std::cout << "ptxts[0]: " << ptxts[0] << endl;
  ea.decode(ptxts[0], ptxt);
  std::cout << "ptxts: " << ptxts << endl;
  std::cout << "ptxts[0]: " << ptxts[0] << endl;
  //vector<long> input1;
  //convert(input, input1);
  //std::cout << "p0 before encode: " << p0 << endl;
  //ea.encode(ptxt, p0);
  std::cout << "ptxt: " << ptxt << endl;
  //std::cout << "p0 after encode: " << p0 << endl;
  //ea.encrypt(c0, publicKey, p0);
  ea.encrypt(c0, publicKey, ptxts);
  //ea.encrypt(c0, publicKey, p0);
  // {ZZX ppp0; ea.encode(ppp0, p0); c0.DummyEncrypt(ppp0);} // dummy encryption
  ea.encrypt(c1, publicKey, p1); // real encryption
  ea.encrypt(c2, publicKey, p2); // real encryption
  ea.encrypt(c3, publicKey, p3); // real encryption

  // This is pretty large
  //std::cout << "c0: " << c0 << endl;

  FHE_NTIMER_START(Circuit);

  long shamt = RandomBnd(2*(nslots/2) + 1) - (nslots/2);
              // random number in [-nslots/2..nslots/2]
  std::cout << "shamt = " << shamt << endl;
  long rotamt = RandomBnd(2*nslots - 1) - (nslots - 1);
              // random number in [-(nslots-1)..nslots-1]
  std::cout << "rotamt = " << rotamt << endl;

  // two random constants
  NewPlaintextArray const1(ea);
  NewPlaintextArray const2(ea);
  random(ea, const1);
  random(ea, const2);

  ZZX const1_poly, const2_poly;
  ea.encode(const1_poly, const1);
  ea.encode(const2_poly, const2);

  mul(ea, p1, p0);     // c1.multiplyBy(c0)
  c1.multiplyBy(c0);
  CheckCtxt(c1, "c1*=c0");
  debugCompare(ea,secretKey,p1,c1);

  add(ea, p0, const1); // c0 += random constant
  c0.addConstant(const1_poly);
  CheckCtxt(c0, "c0+=k1");
  debugCompare(ea,secretKey,p0,c0);

  mul(ea, p2, const2); // c2 *= random constant
  c2.multByConstant(const2_poly);
  CheckCtxt(c2, "c2*=k2");
  debugCompare(ea,secretKey,p2,c2);

  NewPlaintextArray tmp_p(p1); // tmp = c1
  Ctxt tmp(c1);
  sprintf(buffer, "c2>>=%d", (int)shamt);
  shift(ea, tmp_p, shamt); // ea.shift(tmp, random amount in [-nSlots/2,nSlots/2])
  ea.shift(tmp, shamt);
  CheckCtxt(tmp, buffer);
  debugCompare(ea,secretKey,tmp_p,tmp);

  add(ea, p2, tmp_p);  // c2 += tmp
  c2 += tmp;
  CheckCtxt(c2, "c2+=tmp");
  debugCompare(ea,secretKey,p2,c2);

  sprintf(buffer, "c2>>>=%d", (int)rotamt);
  rotate(ea, p2, rotamt); // ea.rotate(c2, random amount in [1-nSlots, nSlots-1])
  ea.rotate(c2, rotamt);
  CheckCtxt(c2, buffer);
  debugCompare(ea,secretKey,p2,c2);

  ::negate(ea, p1); // c1.negate()
  c1.negate();
  CheckCtxt(c1, "c1=-c1");
  debugCompare(ea,secretKey,p1,c1);

  mul(ea, p3, p2); // c3.multiplyBy(c2) 
  c3.multiplyBy(c2);
  CheckCtxt(c3, "c3*=c2");
  debugCompare(ea,secretKey,p3,c3);

  sub(ea, p0, p3); // c0 -= c3
  c0 -= c3;
  CheckCtxt(c0, "c0=-c3");
  debugCompare(ea,secretKey,p0,c0);

  c0.cleanUp();
  c1.cleanUp();
  c2.cleanUp();
  c3.cleanUp();

  FHE_NTIMER_STOP(Circuit);

  NewPlaintextArray pp0(ea);
  NewPlaintextArray pp1(ea);
  NewPlaintextArray pp2(ea);
  NewPlaintextArray pp3(ea);
   
  ea.decrypt(c0, secretKey, pp0);
  ea.decrypt(c1, secretKey, pp1);
  ea.decrypt(c2, secretKey, pp2);
  ea.decrypt(c3, secretKey, pp3);
   
  if (equals(ea, pp0, p0) && equals(ea, pp1, p1)
      && equals(ea, pp2, p2) && equals(ea, pp3, p3))
       std::cout << "GOOD\n";
  else std::cout << "BAD\n";

}
