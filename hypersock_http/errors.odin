package hypersock_http

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

io_error :: proc() -> os.Error {
	when ODIN_OS == .Linux {
		err: os.Error = os.Platform_Error.EIO
		return err
	} else when ODIN_OS == .Windows {
		return os.Platform_Error(win32.ERROR_INVALID_HANDLE)
	} else {
		return io.Error.Unknown
	}
}

not_found_error :: proc() -> os.Error {
	when ODIN_OS == .Linux {
		err: os.Error = os.Platform_Error.ENOENT
		return err
	} else when ODIN_OS == .Windows {
		return os.Platform_Error(win32.ERROR_FILE_NOT_FOUND)
	} else {
		return os.General_Error.Not_Exist
	}
}

not_connected_error :: proc() -> os.Error {
	when ODIN_OS == .Linux {
		err: os.Error = os.Platform_Error.ENOTCONN
		return err
	} else when ODIN_OS == .Windows {
		return os.Platform_Error(win32.WSAENOTCONN)
	} else {
		return os.General_Error.Invalid_Command
	}
}
