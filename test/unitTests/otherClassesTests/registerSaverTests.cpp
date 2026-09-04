#include "../catch.hpp"
#include <string.h>
#include "../../../include/registerSaver.hpp" /* brings in ptracer.hpp: struct user_regs_struct and REG_* per architecture */


/**
 * Tests for the class registerSaver
 */

TEST_CASE("registerSaver throws errors when appropriate", "registerSaver"){
  registerSaver rs;

  SECTION("empty pop throws error"){
    REQUIRE_THROWS_WITH( rs.popRegisterState(), "dettrace runtime exception: Attempting to pop from an empty registerSaver.\n");
  }

  SECTION("full push throws error"){
    struct user_regs_struct regs;
    rs.pushRegisterState(regs);
    REQUIRE_THROWS_WITH( rs.pushRegisterState(regs), "dettrace runtime exception: Attempting to push to a filed registerSaver.\n");
  }

}

TEST_CASE("registerSaver retrieves what is pushed correctly", "registerSaver"){
  registerSaver rs;

  SECTION("push -> pop returns correct state"){
    struct user_regs_struct original = {0xaa, 0xbb, 0xcc};
    rs.pushRegisterState(original);

    struct user_regs_struct returned = rs.popRegisterState();
    
    REQUIRE(memcmp(&original, &returned, sizeof(original)) == 0);


    SECTION("push -> pop -> push -> pop returnes correct state"){
      struct user_regs_struct second = {0xdd, 0xee, 0xff};
      rs.pushRegisterState(second);
      
      struct user_regs_struct returned_second = rs.popRegisterState();
      
      REQUIRE(memcmp(&second, &returned_second, sizeof(second)) == 0);

    }

  }
 
}

TEST_CASE("registerSaver has a deep copy of values", "registerSaver"){
  registerSaver rs;

  SECTION("modifications to original afte push don't show in pop"){
    struct user_regs_struct original = {0, 1, 2, 3, 4};
    rs.pushRegisterState(original);

    REG_SP(original) = 0xfff;
    REG_IP(original) = 0x123;

    struct user_regs_struct returned = rs.popRegisterState();

    REQUIRE(REG_SP(original) != REG_SP(returned));
    REQUIRE(REG_IP(original) != REG_IP(returned));
  }

  SECTION("returned struct does not point to original one"){
    struct user_regs_struct original = {0, 1, 2, 3, 4};
    rs.pushRegisterState(original);
    struct user_regs_struct returned = rs.popRegisterState();
    
    REQUIRE(&original != &returned);
  }
}
