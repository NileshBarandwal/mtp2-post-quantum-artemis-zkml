\\ ================= CONFIG =================
default(parisize, 64*1024*1024);
max_p = 200;
tries  = 200;

\\ ================= FUNCTION =================
isgood(p, a, b) =
{
  my(E, ord);
  if (Mod(4*a^3 + 27*b^2, p) == 0, return(0));
  E   = ellinit([0,0,0,a,b] * Mod(1,p));
  ord = ellcard(E);
  ord;
}

\\ ================= MAIN =================
{
  my(p, a, b, ord, E, G);
  p = nextprime(2^63 + random(2^62));

  for (pc = 1, max_p,
    while (!isprime(p), p = nextprime(p+1));
    print("Trying p = ", p);

    for (t = 1, tries,
      a   = random(p);
      b   = random(p);
      ord = isgood(p, a, b);
      if (ord <= 1, next());

      if (isprime(ord),
        E = ellinit([0,0,0,a,b] * Mod(1,p));
        G = ellgenerators(E)[1];
        print("FOUND PRIME-ORDER CURVE");
        print("p        = ", p);
        print("a        = ", a);
        print("b        = ", b);
        print("#E       = ", ord);
        print("cofactor = 1");
        print("G        = ", G);
        quit(0)
      )
    );

    p = nextprime(p+1);
  );

  print("No prime-order curve found.");
}
