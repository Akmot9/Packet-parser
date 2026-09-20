// Serveur omniORB du labo GIOP : voir tools/capture_giop.sh.
#include <fstream>
#include <unistd.h>

#include "lab.hh"

class EchoImpl : public POA_Lab::Target {
  Lab::Target_var target_;

public:
  explicit EchoImpl(Lab::Target_ptr target = Lab::Target::_nil())
      : target_(Lab::Target::_duplicate(target)) {}

  char* echo(const char* s) override { return CORBA::string_dup(s); }
  char* big(const char* s) override { return CORBA::string_dup(s); }
  char* slow(const char* s) override {
    sleep(3);
    return CORBA::string_dup(s);
  }
  void fail() override { throw Lab::Failure("lab exception"); }
  void forward() override {
    // omniORB traduit cette exception en Reply LOCATION_FORWARD ; la cible,
    // elle, repond normalement a la requete reemise.
    if (!CORBA::is_nil(target_))
      throw omniORB::LOCATION_FORWARD(CORBA::Object::_duplicate(target_), 0);
  }
  void fire(const char*) override {}
};

static void write_ior(CORBA::ORB_ptr orb, CORBA::Object_ptr ref, const char* path) {
  CORBA::String_var ior = orb->object_to_string(ref);
  std::ofstream(path) << ior.in();
}

int main(int argc, char** argv) {
  CORBA::ORB_var orb = CORBA::ORB_init(argc, argv);
  CORBA::Object_var obj = orb->resolve_initial_references("RootPOA");
  PortableServer::POA_var poa = PortableServer::POA::_narrow(obj);

  EchoImpl* target = new EchoImpl();
  PortableServer::ObjectId_var target_id = poa->activate_object(target);
  Lab::Target_var target_ref = target->_this();

  EchoImpl* servant = new EchoImpl(target_ref);
  PortableServer::ObjectId_var servant_id = poa->activate_object(servant);
  Lab::Target_var ref = servant->_this();

  // Objet desactive : toute requete vers lui rend SYSTEM_EXCEPTION
  // (OBJECT_NOT_EXIST).
  EchoImpl* ghost = new EchoImpl();
  PortableServer::ObjectId_var ghost_id = poa->activate_object(ghost);
  Lab::Target_var ghost_ref = ghost->_this();
  poa->deactivate_object(ghost_id);

  write_ior(orb, ref, "/lab/echo.ior");
  write_ior(orb, ghost_ref, "/lab/ghost.ior");

  PortableServer::POAManager_var manager = poa->the_POAManager();
  manager->activate();
  orb->run();
  return 0;
}
