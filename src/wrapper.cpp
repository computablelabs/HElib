#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/operators.h>

//#include "FHE.h"
//#include <NTL/ZZ.h>
//#include <NTL/lip.h>
//#include <NTL/tools.h>
//#include <NTL/vector.h>
//#include <NTL/SmartPtr.h>
//#include <NTL/sp_arith.h>
#include "Pet.h"
#include "Ctxt.h"

int add(int i, int j) {
    return i + j;
}

namespace py = pybind11;

using namespace pybind11::literals;
using namespace std;

PYBIND11_MODULE(hepy, m) {

    // Wrapping for class SKHanlde in Ctxt.h
    py::class_<SKHandle>(m, "SKHandle")
      .def(py::init<long, long, long>())
      .def("setBase", &SKHandle::setBase)
      .def("isBase", &SKHandle::isBase)
      .def("setOne", &SKHandle::setOne)
      .def(py::self == py::self)
      .def(py::self != py::self)
      .def("getPowerOfS", &SKHandle::getPowerOfS)
      .def("getPowerOfX", &SKHandle::getPowerOfX)
      .def("getSecretKeyID", &SKHandle::getSecretKeyID);
      // TODO: There are a couple SKHandle methods I can't
      // quite figure out how to wrap. Come back and add
      // those later.


    m.doc() = R"pbdoc(
        Homomorphic Encryption in Python 
        -----------------------

        .. currentmodule:: hepy 

        .. autosummary::
           :toctree: _generate

           subtract
    )pbdoc";

#ifdef VERSION_INFO
    m.attr("__version__") = VERSION_INFO;
#else
    m.attr("__version__") = "dev1";
#endif
}
