function level3() {
  const x = null;
  return x.toString(); // TypeError
}

function level2() {
  return level3();
}

function level1() {
  return level2();
}

level1();
