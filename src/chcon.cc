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

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <CLI/CLI.hpp>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <selinux/selinux.h>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

enum class TraversalType : uint8_t
{
  NoFollowLinks = 0,
  FollowLinksToDirs,
  FollowAllLinks,
};

struct Options
{
  std::string context;
  std::vector<std::string> files;
  std::string user;
  std::string role;
  std::string range;
  std::string type;
  std::string reference_file;
  /* When true, on supported platforms, change the context of where
     symbolic links may point to instead of just the links themselves.  */
  bool dereference = true;
  bool no_preserve_root = true;
  bool recursive = false;
  bool verbose = false;
  TraversalType traversal_type = TraversalType::NoFollowLinks;
};

Options opts;
char *progname;

static bool
change_context (const fs::path &path)
{
  bool ok = true;
  /* TODO: impl.  */
  return ok;
}

namespace handlers
{

/* Forward decls.  */
bool
file (const fs::path &path);

bool
directory (const fs::path &path);

bool
symlink (const fs::path &path);

bool
file (const fs::path &path)
{
  return change_context (path);
}

bool
directory (const fs::path &path)
{
  auto ec = std::error_code ();
  auto dir_iter = fs::directory_iterator (path, ec);
  if (ec)
    {
      std::cerr << progname << ": error: could not open filesystem object '"
                << path.string () << "': " << ec.message () << '\n';
      return false;
    }
  if (!opts.recursive)
    {
      if (!change_context (path))
        return false;
      return true;
    }
  bool ok = true;
  for (const auto &entry : dir_iter)
    {
      /* Obtain the status of the symlink itself instead of where it points to.  */
      auto status = fs::symlink_status (entry, ec);
      if (ec)
        {
          std::cerr << progname
                    << ": error: could not get status of filesystem object '"
                    << entry.path ().string () << "': " << ec.message ()
                    << '\n';
          ok = false;
          continue;
        }
      switch (status.type ())
        {
        case fs::file_type::directory:
          if (!handlers::directory (entry))
            ok = false;
          break;
        case fs::file_type::symlink:
          if (!handlers::symlink (entry))
            ok = false;
          break;
        default:
          if (handlers::file (entry))
            ok = false;
          break;
        }
    }
  return ok;
}

bool
symlink (const fs::path &path)
{
  if (opts.dereference)
    {
      auto ec = std::error_code ();
      /* Obtain the status of the where the symlink points to.  */
      auto status = fs::status (path, ec);
      if (ec)
        {
          std::cerr << progname
                    << ": error: could not get status of filesystem object '"
                    << path.string () << "': " << ec.message ()
                    << '\n';
          return false;
        }
      switch (status.type ())
        {
        case fs::file_type::directory:
          return handlers::directory (path);
        case fs::file_type::symlink:
          if (opts.traversal_type != TraversalType::FollowAllLinks)
            return change_context (path);
          else
            return handlers::symlink (path);
        default:
          if (opts.traversal_type != TraversalType::FollowAllLinks)
            return change_context (path);
          else
            return handlers::file (path);
        }
    }
  else
    {
      /* Operate on the symlink itself.  */
      return change_context (path);
    }
}

} // namespace handlers

static bool
do_chcon (const std::vector<fs::path> &files)
{
  /* While iterating over the contents of a directory, its contents may change,
     causing us to potentially operate on a filesystem object that no longer exists.
     It is possible to slightly alleviate this by getting a dirfd, iterating over the
     filesystem on unix-like operating systems is inherently racy, so only worry about
     robustness when actually attempting to operate on an object.  */
  bool ok = true;

  for (const auto &file : files)
    {
      std::error_code ec;
      auto s = fs::status (file, ec);

      if (ec)
        {
          std::cerr << progname << ": cannot access '" << file.string ()
                    << "': " << ec.message () << '\n';
          ok = false;
          continue; /* Skip past this file, but don't early-exit.  */
        }

      /* Kick-start the recursion.  */
      switch (s.type ())
        {
        case fs::file_type::directory:
          /* Only worry about operating recursively for directories.  */
          if (!handlers::directory (file))
            ok = false;
          break;
        case fs::file_type::symlink:
          /* As we are a symlink, we need to consider the dereference option. */
          if (!handlers::symlink (file))
            ok = false;
          break;
        default:
          /* Proceed as if a regular file; we don't need to worry about any extra
             options if not a symlink or directory.  */
          if (!handlers::file (file))
            ok = false;
          break;
        }
    }

  return ok;
}

static std::vector<fs::path>
to_paths (const std::vector<std::string> &vec)
{
  std::vector<fs::path> ret;
  ret.reserve (vec.size ());

  std::transform (vec.begin (), vec.end (), std::back_inserter (ret),
                 [] (const std::string &str) {
                   /* While the constructor for fs::path may throw an impl
                      defined exception, other than allocation failure,
                      there isn't really a good reason to throw, so don't
                      bother attempting to catch it.  */
                   return fs::path (str);
                 });

  return ret;
}

int
main (int argc, char **argv)
{
  progname = argv[0];
  CLI::App app{"Change file security context"};

  /* We reserve the shorthand '-h' flag for ourselves.  */
  app.set_help_flag ("--help", "Print this help message and exit");
  app.add_option ("CONTEXT", opts.context, "Security context to apply");
  /* Files are required, but we handle checking for them ourselves later.  */
  app.add_option ("FILE", opts.files, "files to modify");
  app.add_flag ("--dereference", opts.dereference,
                "Affect the referent of each symbolic link (default)");
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
  app.add_flag ("-H", [&] (size_t) { opts.traversal_type = TraversalType::FollowLinksToDirs; },
                "Traverse symbolic links to directories on command line");
  app.add_flag ("-L", [&] (size_t) { opts.traversal_type = TraversalType::FollowAllLinks; },
                "Traverse every symbolic link to a directory");
  app.add_flag ("-P", [&] (size_t) { opts.traversal_type = TraversalType::NoFollowLinks; },
                "Do not traverse any symbolic links (default)");

  CLI11_PARSE (app, argc, argv);

  const bool component_specified = !opts.user.empty ()
    || !opts.role.empty ()
    || !opts.type.empty ()
    || !opts.range.empty ();

  bool dereference = true;

  if (opts.recursive)
    {
      if (opts.traversal_type == TraversalType::NoFollowLinks)
        {
          if (opts.dereference)
            {
              std::cerr << progname
                        << ": error: -R --dereference requires either -H or -L\n";
              return 1;
            }
          dereference = false;
        }
      /* As we default to dereferencing symlinks,
         we do not need to modify the dereference bool here.  */
      if (opts.traversal_type != TraversalType::NoFollowLinks
          && !opts.dereference)
        {
          std::cerr << progname << ": error: -R -h requires -P\n";
          return 1;
        }
    }
  else
    {
      /* As we default to dereferencing symlinks,
         we do not need to modify the dereference bool here.  */
      opts.traversal_type = TraversalType::NoFollowLinks;
    }

  opts.dereference = dereference;

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

  if (!opts.reference_file.empty ())
    {
      char *context = nullptr;
      if (getfilecon (opts.reference_file.c_str (),
                      &context) < 0)
        {
          std::cerr << progname << ": failed to get security context of '"
                    << opts.reference_file << "': " << strerror (errno) << '\n';
          return 1;
        }
    }
  else if (!opts.context.empty ())
    {
      /* Check the validity of the provided context.  */
      if (is_selinux_enabled () > 0
          && security_check_context (opts.context.c_str ()) < 0)
        {
          std::cerr << progname << ": invalid context: '" << opts.context
                    << "': " << strerror (errno) << '\n';
          return 1;
        }
    }

  if (opts.recursive
      && !opts.no_preserve_root)
    {
      /* TODO: validate we are not operating on /.  */
    }

  const auto files = to_paths (opts.files);
  const bool ok = do_chcon (files);

  return ok ? 0 : 1;
}
