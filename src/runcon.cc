/* This file is a part of SELinux Utils.
 * Copyright (C) Rahul Sandhu <rahul@sandhuservices.dev>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* This implementation of runcon(1) is largely based on the implementation
 * provided by the GNU project in their coreutils suite.  */

#include <CLI/CLI.hpp>
#include <selinux/selinux.h>
#include <string>
#include <vector>

struct Options
{
  std::string context;
  bool compute = false;
  std::string type;
  std::string user;
  std::string role;
  std::string range;
  std::vector<std::string> command;
};

Options opts;
std::string progname;

int
main (int argc, char **argv)
{
  progname = argv[0];
  CLI::App app{R"(Run a program in a different SELinux security context.
With neither CONTEXT nor COMMAND, print the current security context.)"};

  app.set_help_flag ("--help", "Display this help and exit");
  app.add_option ("CONTEXT", opts.context, "Complete security context");
  app.add_option ("-c,--compute", opts.compute,
                  "Compute process transition context before modifying");
  app.add_option ("-t,--type", opts.type, "Type (for same role as parent)");
  app.add_option ("-u,--user", opts.user, "User identity");
  app.add_option ("-r,--role", opts.role, "Role");
  app.add_option ("-l,--range", opts.range, "Levelrange");
  app.add_option ("COMMAND", opts.command, "Command to run (with arguments)")
    ->allow_extra_args ();

  CLI11_PARSE (app, argc, argv);

  if (is_selinux_enabled () != 1)
    {
      std::cerr << progname << " may be used only on a SELinux kernel\n";
      return 1;
    }

  return 0;
}
