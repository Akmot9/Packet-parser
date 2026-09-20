// Client omniORB du labo GIOP : voir tools/capture_giop.sh.
// Usage : client <scenario> [options -ORB...]
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unistd.h>

#include "lab.hh"

static CORBA::Object_ptr read_ref(CORBA::ORB_ptr orb, const char* path) {
  std::ifstream in(path);
  std::stringstream ior;
  ior << in.rdbuf();
  return orb->string_to_object(ior.str().c_str());
}

template <typename Call> static void attempt(const char* what, Call call) {
  try {
    call();
    std::cout << "  " << what << " : ok" << std::endl;
  } catch (const Lab::Failure& ex) {
    std::cout << "  " << what << " : Lab::Failure(" << ex.why.in() << ")" << std::endl;
  } catch (const CORBA::SystemException& ex) {
    std::cout << "  " << what << " : CORBA::" << ex._name() << std::endl;
  }
}

int main(int argc, char** argv) {
  std::string scenario = argc > 1 ? argv[1] : "basic";
  CORBA::ORB_var orb = CORBA::ORB_init(argc, argv);

  if (scenario == "ghost") {
    CORBA::Object_var ghost = read_ref(orb, "/lab/ghost.ior");
    attempt("_non_existent", [&] { ghost->_non_existent(); });
    attempt("echo", [&] {
      Lab::Target_var echo = Lab::Target::_unchecked_narrow(ghost);
      CORBA::String_var r = echo->echo("nobody home");
    });
  } else {
    CORBA::Object_var obj = read_ref(orb, "/lab/echo.ior");
    Lab::Target_var echo = Lab::Target::_unchecked_narrow(obj);

    if (scenario == "basic") {
      attempt("echo", [&] { CORBA::String_var r = echo->echo("hello giop"); });
      attempt("fire", [&] { echo->fire("oneway"); });
      attempt("fail", [&] { echo->fail(); });
      attempt("forward", [&] { echo->forward(); });
      attempt("big", [&] {
        std::string payload(20000, 'x');
        CORBA::String_var r = echo->big(payload.c_str());
      });
    } else if (scenario == "timeout") {
      attempt("slow", [&] { CORBA::String_var r = echo->slow("too slow"); });
      // Attend le Reply tardif du serveur (3 s) : il reste dans cette
      // capture au lieu de fuir dans la suivante.
      usleep(3500000);
    } else if (scenario == "idle") {
      // Laisse la connexion oisive assez longtemps pour que le scan du
      // serveur la ferme avec un message CloseConnection.
      attempt("echo", [&] { CORBA::String_var r = echo->echo("then idle"); });
      sleep(6);
    }
  }

  orb->destroy();
  return 0;
}
