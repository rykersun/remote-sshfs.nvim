local utils = require "remote-sshfs.utils"
local ui = require "remote-sshfs.ui"
local handler = require "remote-sshfs.handler"

local config = {}
local hosts = {}
local ssh_configs = {}
local ssh_known_hosts = nil
local sshfs_args = {}

-- Current connection
local sshfs_job_id = nil
local mount_point = nil
local current_host = nil

-- Job currently being intentionally disconnected.
-- Used to suppress expected sshfs stderr such as:
--   "remote host has disconnected"
--   "Killed by signal 15"
local disconnecting_job_id = nil

local M = {}

local function clear_picker_cache()
  pcall(function()
    require("telescope._extensions.remote-sshfs").clear_cache()
  end)

  pcall(function()
    require("remote-sshfs.pickers.snacks").clear_cache()
  end)

  pcall(function()
    require("remote-sshfs.pickers.fzf-lua").clear_cache()
  end)
end

M.setup = function(opts)
  config = opts
  utils.setup_sshfs(config)

  ssh_configs = config.connections.ssh_configs
  ssh_known_hosts = config.connections.ssh_known_hosts
  sshfs_args = config.connections.sshfs_args

  hosts = utils.parse_hosts_from_configs(ssh_configs)
end

M.is_connected = function()
  return sshfs_job_id ~= nil and mount_point ~= nil and current_host ~= nil
end

M.list_hosts = function()
  return hosts
end

M.list_ssh_configs = function()
  return ssh_configs
end

M.get_current_host = function()
  return current_host
end

M.get_current_mount_point = function()
  return mount_point
end

M.reload = function()
  hosts = utils.parse_hosts_from_configs(ssh_configs)
  vim.notify "Reloaded!"
end

M.connect = function(host)
  local remote_host = host["Name"]

  if config.ui.confirm.connect then
    local prompt = "Connect to remote host (" .. remote_host .. ")?"

    ui.prompt_yes_no(prompt, function(item_short)
      ui.clear_prompt()

      if item_short == "y" then
        M.init_host(host)
      end
    end)
  else
    M.init_host(host)
  end
end

M.init_host = function(host, ask_pass)
  -- If another SSHFS process is still around, stop it.
  --
  -- For the normal connect flow, users should disconnect the existing
  -- connection before connecting to another host.
  --
  -- ask_pass is special: the existing sshfs job may be waiting for
  -- authentication, so we stop that process before restarting with
  -- password_stdin.
  if sshfs_job_id then
    vim.fn.jobstop(sshfs_job_id)
  end

  local remote_host = host["Name"]
  local mount_dir = config.mounts.base_dir .. remote_host

  if not ask_pass then
    utils.setup_mount_dir(mount_dir, function()
      M.mount_host(host, mount_dir, ask_pass)
    end)
  else
    M.mount_host(host, mount_dir, ask_pass)
  end
end

M.mount_host = function(host, mount_dir, ask_pass)
  -- Ensure sshfs is available
  if vim.fn.executable "sshfs" == 0 then
    vim.api.nvim_err_writeln "[remote-sshfs] 'sshfs' not found. Please install sshfs to use remote-sshfs."
    return
  end

  -- Use the SSH config alias whenever possible.
  --
  -- For example:
  --
  --   Host dgx
  --       HostName dgx
  --       User voyager
  --
  -- We want sshfs to connect using "dgx" so OpenSSH can apply all
  -- settings from ~/.ssh/config.
  local target_host = host["Name"] or host["HostName"]

  local cmd = { "sshfs" }

  -- Verbose logging
  table.insert(cmd, "-o")
  table.insert(cmd, "LOGLEVEL=VERBOSE")

  -- Custom SSHFS arguments
  for _, value in ipairs(sshfs_args) do
    for _, part in ipairs(vim.split(value, "%s+")) do
      table.insert(cmd, part)
    end
  end

  -- Run sshfs in foreground so Neovim can track the process.
  if config.mounts.unmount_on_exit then
    table.insert(cmd, "-f")
  end

  -- Remote SSH port
  if host["Port"] then
    table.insert(cmd, "-p")
    table.insert(cmd, host["Port"])
  end

  -- Password authentication via stdin
  if ask_pass then
    table.insert(cmd, "-o")
    table.insert(cmd, "password_stdin")
  end

  -- Build remote spec:
  --
  --   [user@]host[:path]
  --
  local spec = target_host

  if host["User"] then
    spec = host["User"] .. "@" .. spec
  end

  spec = spec .. ":" .. (host["Path"] or "")

  table.insert(cmd, spec)

  -- Local mount point
  table.insert(cmd, mount_dir)

  local function ensure_ssh_host_key(callback)
    assert(ssh_known_hosts, "ssh_known_hosts is required")

    local hostname = host["HostName"] or host["Name"]

    -- Build hostname used for known_hosts lookup.
    --
    -- Non-default ports use:
    --
    --   [hostname]:port
    --
    local lookup_host = hostname

    if host["Port"] and host["Port"] ~= "22" then
      lookup_host = "[" .. hostname .. "]:" .. host["Port"]
    end

    -- Check whether the host key already exists.
    local known_info = vim.fn.system {
      "ssh-keygen",
      "-F",
      lookup_host,
      "-f",
      ssh_known_hosts,
    }

    if known_info:find "found" then
      callback()
      return
    end

    -- Retrieve host keys.
    local scan_cmd = { "ssh-keyscan" }

    if host["Port"] then
      table.insert(scan_cmd, "-p")
      table.insert(scan_cmd, host["Port"])
    end

    table.insert(scan_cmd, hostname)

    local scan_result = vim.fn.system(scan_cmd)

    if vim.v.shell_error ~= 0 or scan_result == "" then
      vim.notify("Could not retrieve host keys for " .. hostname, vim.log.levels.ERROR)
      return
    end

    -- Use the first key to show the fingerprint.
    local first_key_line = vim.split(scan_result, "\n")[1]

    if not first_key_line or first_key_line == "" then
      vim.notify("No valid host keys found for " .. hostname, vim.log.levels.ERROR)
      return
    end

    local temp_file = vim.fn.tempname()
    local temp_handle = io.open(temp_file, "w")

    if not temp_handle then
      vim.notify("Could not create temporary file for fingerprint verification", vim.log.levels.ERROR)
      return
    end

    temp_handle:write(first_key_line .. "\n")
    temp_handle:close()

    local fingerprint = vim.fn.system {
      "ssh-keygen",
      "-lf",
      temp_file,
    }

    vim.fn.delete(temp_file)

    if vim.v.shell_error ~= 0 or fingerprint == "" then
      vim.notify("Could not parse fingerprint for " .. hostname, vim.log.levels.ERROR)
      return
    end

    fingerprint = fingerprint:gsub("\n", "")

    local prompt = string.format(
      "The authenticity of host '%s' can't be established.\n%s\nAdd this host key to %s? (y/n)",
      hostname,
      fingerprint,
      ssh_known_hosts
    )

    vim.schedule(function()
      ui.prompt_yes_no(prompt, function(item_short)
        ui.clear_prompt()

        if item_short ~= "y" then
          vim.notify("Aborted adding host key for " .. hostname, vim.log.levels.WARN)
          return
        end

        local scan_cmd_final = { "ssh-keyscan" }

        if host["Port"] then
          table.insert(scan_cmd_final, "-p")
          table.insert(scan_cmd_final, host["Port"])
        end

        table.insert(scan_cmd_final, hostname)

        local result = vim.fn.system(scan_cmd_final)

        if vim.v.shell_error ~= 0 or result == "" then
          vim.notify("Failed to retrieve host key for " .. hostname, vim.log.levels.ERROR)
          return
        end

        local file_handle = io.open(ssh_known_hosts, "a")

        if not file_handle then
          vim.notify("Failed to write to " .. ssh_known_hosts, vim.log.levels.ERROR)
          return
        end

        file_handle:write(result)

        if not result:match "\n$" then
          file_handle:write "\n"
        end

        file_handle:close()

        vim.notify("Host key added for " .. hostname, vim.log.levels.INFO)

        callback()
      end)
    end)
  end

  local function start_job()
    vim.notify("Connecting to host (" .. (host["Name"] or target_host) .. ")...")

    local skip_clean = false
    local spec_mount_point = mount_dir .. "/"
    local spec_host = host

    local id = vim.fn.jobstart(cmd, {
      on_stdout = function(jid, data)
        -- Ignore output generated by an intentional disconnect.
        if jid == disconnecting_job_id then
          return
        end

        handler.sshfs_wrapper(data, host, mount_dir, function(event)
          if event == "ask_pass" then
            skip_clean = true
            M.init_host(host, true)
          end
        end)
      end,

      on_stderr = function(jid, data)
        -- sshfs commonly writes expected shutdown messages to stderr:
        --
        --   remote host has disconnected
        --   Killed by signal 15
        --
        -- Do not report those as connection failures when the user
        -- intentionally called RemoteSSHFSDisconnect.
        if jid == disconnecting_job_id then
          return
        end

        handler.sshfs_wrapper(data, host, mount_dir, function(event)
          if event == "ask_pass" then
            skip_clean = true
            M.init_host(host, true)
          end
        end)
      end,

      on_exit = function(jid, _, data)
        -- Expected exit caused by RemoteSSHFSDisconnect.
        if jid == disconnecting_job_id then
          disconnecting_job_id = nil
          return
        end

        -- Ignore stale jobs.
        if jid ~= sshfs_job_id then
          return
        end

        handler.on_exit_handler(data, mount_dir, skip_clean, function()
          sshfs_job_id = nil
          mount_point = nil
          current_host = nil
        end)
      end,
    })

    if id <= 0 then
      vim.notify("[remote-sshfs] failed to start sshfs (code " .. tostring(id) .. ")", vim.log.levels.ERROR)
      return
    end

    sshfs_job_id = id
    mount_point = spec_mount_point
    current_host = spec_host

    if ask_pass then
      local password = vim.fn.inputsecret "Enter password for host: "
      vim.fn.chansend(id, password .. "\n")
    end
  end

  ensure_ssh_host_key(function()
    start_job()
  end)
end

M.unmount_host = function()
  if not mount_point then
    vim.notify("No remote SSHFS filesystem is currently mounted.", vim.log.levels.INFO)
    return
  end

  local target = mount_point:gsub("/$", "")

  -- Mark this SSHFS job as intentionally disconnecting before doing
  -- anything that could make sshfs emit stderr or exit.
  disconnecting_job_id = sshfs_job_id

  -- If Neovim's cwd is inside the mounted filesystem, leave it first.
  --
  -- Otherwise macOS/macFUSE may reject the unmount because the
  -- filesystem is still being used as Neovim's working directory.
  local cwd = vim.fn.getcwd()

  if cwd == target or vim.startswith(cwd, target .. "/") then
    vim.cmd("cd " .. vim.fn.fnameescape(vim.fn.expand "~"))
  end

  local cmd

  -- macOS / macFUSE
  if vim.fn.has "macunix" == 1 then
    cmd = {
      "umount",
      target,
    }

  -- Linux, newer FUSE
  elseif vim.fn.executable "fusermount3" == 1 then
    cmd = {
      "fusermount3",
      "-u",
      target,
    }

  -- Linux, older FUSE
  elseif vim.fn.executable "fusermount" == 1 then
    cmd = {
      "fusermount",
      "-u",
      target,
    }

  -- Generic fallback
  else
    cmd = {
      "umount",
      target,
    }
  end

  local output = vim.fn.system(cmd)

  if vim.v.shell_error ~= 0 then
    -- Unmount failed, therefore this is no longer considered an
    -- intentional disconnect. Keep all connection state intact so the
    -- user can retry.
    disconnecting_job_id = nil

    vim.notify("Failed to unmount " .. target .. ":\n" .. output, vim.log.levels.ERROR)

    return
  end

  -- After a successful unmount, sshfs normally exits by itself.
  --
  -- If it is somehow still alive, stop the foreground process.
  if sshfs_job_id then
    local result = vim.fn.jobwait({ sshfs_job_id }, 0)

    local status = result[1]

    -- -1 means the job is still running.
    if status == -1 then
      vim.fn.jobstop(sshfs_job_id)
    end
  end

  sshfs_job_id = nil
  mount_point = nil
  current_host = nil

  clear_picker_cache()

  vim.notify("Remote SSHFS filesystem unmounted successfully.", vim.log.levels.INFO)
end

return M
