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

/* This implementation of chcon(1) is largely based on the implementation
 * provided by the GNU project in their coreutils suite.  */

#include <CLI/CLI.hpp>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

struct Options
{
  std::string context;
  std::vector<std::string> files;
  std::string user;
  std::string role;
  std::string range;
  std::string type;
  std::string reference_file;
  bool dereference = true;
  bool no_preserve_root = true;
  bool recursive = false;
  bool verbose = false;
  char traverse_option = 'P';
  /* When true, on supported platforms, change the context of where
     symbolic links may point to instead of just the links themselves.  */
  bool affect_symlink_base = true;
};

int
main (int argc, char **argv)
{
  std::string_view progname = argv[0];
  CLI::App app{"Change file security context"};
  Options opts;

  /* We reserve the shorthand '-h' flag for ourselves.  */
  app.set_help_flag ("--help", "Print this help message and exit");
  app.add_option ("CONTEXT", opts.context, "Security context to apply");
  /* Files are required, but we handle checking for them ourselves later.  */
  app.add_option ("FILE", opts.files, "files to modify");
  app.add_flag ("--dereference", opts.dereference,
                "Affect the referent of each symbolic link");
  app.add_flag ("-h,--no-dereference",
                [&] (size_t) { opts.dereference = false; },
                "Affect symbolic links instead of referenced files");
  app.add_option ("-u,--user", opts.user, "Set user in the target security context");
  app.add_option ("-r,--role", opts.role, "Set role in the target security context");
  app.add_option ("-t,--type", opts.role, "Set type in the target security context");
  app.add_option ("-l,--range", opts.role, "Set range in the target security context");
  app.add_flag ("--no-preserve-root", opts.no_preserve_root, "Do not treat '/' specially");
  app.add_flag ("--preserve-root", [&] (size_t) { opts.no_preserve_root = false; },
                "Fail to operate recursively on '/'");
  app.add_option ("--reference", opts.reference_file, "Use RFILE's security context");
  app.add_flag ("-R,--recursive", opts.recursive,
                "Operate on files and directories recursively");
  app.add_flag ("-v,--verbose", opts.verbose, "Output a diagnostic for every file processed");
  app.add_flag ("-H", [&] (size_t) { opts.traverse_option = 'H'; },
                "Traverse symbolic links to directories on command line");
  app.add_flag ("-L", [&] (size_t) { opts.traverse_option = 'L'; },
                "Traverse every symbolic link to a directory");
  app.add_flag ("-P", [&] (size_t) { opts.traverse_option = 'P'; },
                "Do not traverse any symbolic links (default)");

  CLI11_PARSE (app, argc, argv);

  const bool component_specified = !opts.user.empty ()
    || !opts.role.empty ()
    || !opts.type.empty ()
    || !opts.range.empty ();

  if (opts.recursive)
    {
      /* As we default to affecting symlink bases,
         we do not need to modify opts.affect_symlink_base here.  */
      if (opts.traverse_option == 'P'
          && opts.dereference)
        {
          std::cerr << progname
                    << ": error: -R --dereference requires either -H or -L\n";
          return 1;
        }
      if (opts.traverse_option != 'P')
        {
          if (!opts.dereference)
            {
              std::cerr << progname << ": error: -R -h requires -P\n";
              return 1;
            }
          opts.affect_symlink_base = false;
        }
    }

  if (component_specified
      && !opts.reference_file.empty ())
    {
      /* Conflicting security context specifiers given, bail.  */
      std::cerr << progname << ": conflicting security context specifiers given\n"
                << "Type '" << progname << " --help' for more information.\n";
      return 1;
    }

  if (!opts.context.empty ()
      && (component_specified
          || !opts.reference_file.empty ()))
    {
      /* As we have been provided a component of a context, all arguments
         without switches henceforth are to be treated as files.  */
      opts.files.emplace_back (opts.context);
      opts.context = ""; /* Reset the context field.  */
    }

  /* At this point, all possible arguments that may make up files have
   been provided, so check if it is empty or not now.  */
  if (opts.files.empty ())
    {
      std::cerr << progname << ": missing operand FILES\n"
                << "Type '" << progname << " --help' for more information.\n";
      return 1;
    }

  return 0;
}
