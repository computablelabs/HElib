import hepy

def test_SKHandle_construction():
  """Tests that SKHandle object can be constructed."""
  power_of_S = 0
  power_of_X = 1
  secret_key_id = 0
  handle = hepy.SKHandle(power_of_S, power_of_X,
                         secret_key_id)

def test_SKHandle_equality():
  """Tests that SKHandle equality works."""
  power_of_S = 0
  power_of_X = 1
  secret_key_id = 0
  handle = hepy.SKHandle(power_of_S, power_of_X,
                         secret_key_id)

  power_of_S = 0
  power_of_X = 1
  secret_key_id = 0
  handle2 = hepy.SKHandle(power_of_S, power_of_X,
                         secret_key_id)
  assert handle == handle2

def test_SKHandle_not_equality():
  """Tests that different SKHandle objects not equal."""
  power_of_S = 0
  power_of_X = 1
  secret_key_id = 0
  handle = hepy.SKHandle(power_of_S, power_of_X,
                         secret_key_id)

  power_of_S = 1
  power_of_X = 1
  secret_key_id = 0
  handle2 = hepy.SKHandle(power_of_S, power_of_X,
                          secret_key_id)
  assert handle != handle2

def test_FHEcontext_init():
  # TODO(rbharath): What do these numbers mean? Need to
  # add a docstring explaining.
  m = 5
  p = 7
  r = 3
  gens = []
  ords = []
  fhe_context = hepy.FHEcontext(m, p, r, gens, ords)


if __name__ == "__main__":
  print("Running SKHandle tests")
  test_SKHandle_construction()
  test_SKHandle_equality()
  test_SKHandle_not_equality()
  print("Running FHEcontext tests")
  test_FHEcontext_init()
  print("All tests passed")
