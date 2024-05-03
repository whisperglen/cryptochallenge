
#include "hextobase64.h"
#include "utils.h"
#include "aes_helper.h"
#include "mt19937.h"
#include <iostream>
#include <string>
#include <fstream>
#include <windows.h>
#include <cassert>
#include "bignum.h"

using std::string;
using std::cin;
using std::cout;
using std::endl;

int call_challenge33();
int call_challenge34();
int call_challenge35();
int call_challenge36();
int call_challenge37();
int call_challenge38();
int call_challenge39();
int call_challenge40();

int call_set5()
{
    int retcode = 0;
    std::cout << "This is Set 5\n";

    retcode = call_challenge33();

    return retcode;
}

/*
    p = 37
    g = 5

    a = rand % p(37)            34
    A = (g(5) ** a) % p(37)     3

    b = rand % p(37)            15
    B = (g(5) ** b) % p(37)     29

    A, B public keys

    s = (B ** a) %p(37)         11
    s = (A ** b) %p(37)         11
*/
int call_challenge33()
{
    membuf p = MEMBUF_INITIALISER, g = MEMBUF_INITIALISER;
    membuf a = MEMBUF_INITIALISER, A = MEMBUF_INITIALISER;
    membuf b = MEMBUF_INITIALISER, B = MEMBUF_INITIALISER;
    membuf s1 = MEMBUF_INITIALISER, s2 = MEMBUF_INITIALISER;

    bnum_from_int(&p, 37);
    bnum_from_int(&g, 5);

    bnum_from_int(&a, 2772);
    bnum_div(&a, &p, NULL, &a);

    bnum_modexp(&g, &a, &p, &A);

    bnum_from_int(&b, 3678);
    bnum_div(&b, &p, NULL, &b);

    bnum_modexp(&g, &b, &p, &B);

    bnum_modexp(&B, &a, &p, &s1);
    bnum_modexp(&A, &b, &p, &s2);

    membuf x = MEMBUF_INITIALISER, y = MEMBUF_INITIALISER, z = MEMBUF_INITIALISER, t = MEMBUF_INITIALISER;

    bnum_from_int(&g, 2);

    bnum_from_chars(&p, "896320919633919", 10);
    bnum_from_chars(&a, "722825936385968", 10);

    bnum_div(&a, &p, NULL, &a);
    bnum_modexp(&g, &a, &p, &A);

    bnum_from_chars(&p, "2410312426921032588552076022197566074856950548502459942654116941"
                        "9581088316826122288900938582613416146732271414779040121965036489"
                        "5705058263194273070680500922306273474534107340669624601458936165"
                        "9774041027169249453200378729434170325843778659198143763193776859"
                        "8695240889401955773461198435453015470437472077499697637500843089"
                        "2633929555996888245787241299381012913029459299994792636526405928"
                        "4647209730384947211681434464714438488520940127459844288859336526"
                        "896320919633919", 10);

    bnum_from_chars(&a, "1235396053420411732940144135433983228811154023328513719560153963"
                        "9282913087123690170510099354005083534967437974059471803241982550"
                        "8319279187548309085180051502720461800812625989138639794657865884"
                        "1000808711263935810059050865848883285190469674211077297643430847"
                        "3210463913609030620471517103542888947938569574086606009687801431"
                        "7733973091995821325050819221202125917222227813957624531115871018"
                        "5201210137339628868960642103947661992526732610865136681230026400"
                        "722825936385968", 10);

    bnum_from_chars(&b, "1686950063594557687601405790559798737434000394463620510496212089"
                        "2220622443599148607551561408596607430629158811578765867729580366"
                        "0133840071085085293924439328393258539371893005314376422775497554"
                        "5613305764209391796908004067815283247897424151235188954344957200"
                        "9567007154387024327414015358470640868452043896334058416469355159"
                        "4350120368053582409004209623492676177090617186565927528767864970"
                        "2314018432218897169710427637032147793841009686941816434802928580"
                        "795508298664943", 10);

    bnum_div(&a, &p, NULL, &a);
    bnum_modexp(&g, &a, &p, &A);

    bnum_div(&b, &p, NULL, &b);
    bnum_modexp(&g, &b, &p, &B);

    bnum_modexp(&B, &a, &p, &s1);
    bnum_modexp(&A, &b, &p, &s2);
    if (0 == bnum_compare(&s1, &s2))
    {
        cout << "Session keys match!\n";
    }
    else
    {
        cout << "Session keys do NOT match!\n";
    }


    return 0;
}