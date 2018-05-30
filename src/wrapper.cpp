#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/operators.h>
#include "Ctxt.h"
#include "FHEContext.h"

namespace py = pybind11;

using namespace pybind11::literals;
using namespace std;

PYBIND11_MODULE(hepy, m) {

    // TODO(rbharath): These wrappers need comment strings
    // and default arguments added for them.

    // Wrapping for class SKHandle in Ctxt.h
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
    
    // Wrapping for class FHEcontext in FHEContext.h
    py::class_<FHEcontext>(m, "FHEcontext")
      .def(py::init<unsigned long, unsigned long, unsigned long, const vector<long>&, const vector<long>&>());

    m.def("FindM", &FindM,
          "Returns smallest parameter m satisfying various constraints.",
          py::arg("k"),
          py::arg("L"),
          py::arg("c"),
          py::arg("p"),
          py::arg("d"),
          py::arg("s"),
          py::arg("chosen_m"),
          py::arg("verbose")=false);


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
