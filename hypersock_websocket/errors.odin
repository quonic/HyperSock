package hypersock_websocket

import "core:io"
import "core:os"
import win32 "core:sys/windows"

invalid_parameter_error :: proc() -> os.Error {
	when ODIN_OS == .Linux {
		err: os.Error = os.Platform_Error.EINVAL
		return err
	} else when ODIN_OS == .Windows {
		return os.Platform_Error(win32.ERROR_INVALID_PARAMETER)
	} else {
		return os.General_Error.Invalid_Command
	}
}

access_denied_error :: proc() -> os.Error {
	when ODIN_OS == .Linux {
		err: os.Error = os.Platform_Error.EACCES
		return err
	} else when ODIN_OS == .Windows {
		return os.Platform_Error(win32.ERROR_ACCESS_DENIED)
	} else {
		return io.Error.Permission_Denied
	}
}

not_supported_error :: proc() -> os.Error {
	when ODIN_OS == .Linux {
		err: os.Error = os.Platform_Error.ENOSYS
		return err
	} else when ODIN_OS == .Windows {
		return os.Platform_Error(win32.ERROR_NOT_SUPPORTED)
	} else {
		return io.Error.Unsupported
	}
}

connection_reset_error :: proc() -> os.Error {
	when ODIN_OS == .Linux {
		err: os.Error = os.Platform_Error.ECONNRESET
		return err
	} else when ODIN_OS == .Windows {
		return os.Platform_Error(win32.WSAECONNRESET)
	} else {
		return os.General_Error.Broken_Pipe
	}
}

connection_refused_error :: proc() -> os.Error {
	when ODIN_OS == .Linux {
		err: os.Error = os.Platform_Error.ECONNREFUSED
		return err
	} else when ODIN_OS == .Windows {
		return os.Platform_Error(win32.WSAECONNREFUSED)
	} else {
		return os.General_Error.Invalid_Command
	}
}

would_block_error :: proc() -> os.Error {
	when ODIN_OS == .Linux {
		err: os.Error = os.Platform_Error.EAGAIN
		return err
	} else when ODIN_OS == .Windows {
		return os.Platform_Error(win32.WSAEWOULDBLOCK)
	} else {
		return os.General_Error.Timeout
	}
}
