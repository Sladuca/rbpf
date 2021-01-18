typedef unsigned char uint8_t;
typedef unsigned long int uint64_t;

uint8_t *binary_search(uint8_t *array, uint64_t lo, uint64_t hi, uint8_t item)
{

  if (hi - lo <= 1 && array[lo] == item)
  {
    return &array[lo];
  }
  if (hi - lo <= 1)
  {
    return 0;
  }

  uint64_t mid = hi - lo / 2;
  if (array[mid] < item)
  {
    return binary_search(array, mid, hi, item);
  }
  if (array[mid] > item)
  {
    return binary_search(array, lo, mid, item);
  }
  return &array[mid];
}

extern uint64_t entrypoint(const uint8_t *input)
{
  uint8_t array[27] = {0, 1, 3, 7, 7, 7, 9, 13, 17, 17, 18, 19, 20, 27, 31, 34, 37, 37, 37, 42, 49, 194, 200, 201, 210, 210, 240};

  uint8_t *res = binary_search(array, 0, 26, *input);
  if (res == 0)
  {
    return 255;
  }
  return (uint64_t)(*res);
}