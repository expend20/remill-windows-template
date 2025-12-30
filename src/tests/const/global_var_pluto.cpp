int v = 0x37;

extern "C" int test_me()
{
    return 0x1300 ^ v;
}
