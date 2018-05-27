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

def test_FindM_invocation():
  """Test that FindM can be invoked."""
  plaintext_base_prime = 2
  finite_field_degree = 1
  field_extension_deg = 1
  num_key_columns = 2
  security_parameter = 80
  num_levels = 0
  chosen_cyclotomic_degree = 0
  num_slots = 0
  cyclotomic_degree = hepy.FindM(security_parameter,
                                 num_levels,
                                 num_key_columns,
                                 plaintext_base_prime,
                                 finite_field_degree,
                                 num_slots,
                                 chosen_cyclotomic_degree,
                                 False)


if __name__ == "__main__":
  print("Running SKHandle tests")
  test_SKHandle_construction()
  test_SKHandle_equality()
  test_SKHandle_not_equality()
  print("Running FHEcontext tests")
  test_FHEcontext_init()
  print("Running FindM tests")
  test_FindM_invocation()
  print("All tests passed")
