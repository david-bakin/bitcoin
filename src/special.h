#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

inline bool dsbisenabled = false;
inline void dsbsetenabled(bool b) { dsbisenabled = b; }


template <typename FN>
void dsbout(FN fn)
{
    static std::string filename{"/workspace/data/dsb-bitcoin-debug.log"};
    if (dsbisenabled) {
        std::fstream fb;
        fb.open(filename, std::ios::out|std::ios::app);
        fn(fb);
        fb.close();
    }
}

#define DSBOUT(...) {dsbout([&](std::fstream& fb){fb << __VA_ARGS__ << std::endl;});}
