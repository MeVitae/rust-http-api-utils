#[macro_export]
macro_rules! error_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $Name:ident {
            $($Variant:ident$(($typ:ty))? => $message:expr $(
                => $err:ident => $respond_to:expr
            )?,)*
        }
    ) => {
        $(#[$meta])*
        $vis enum $Name {
            $($Variant$(($typ))?,)*
        }

        $($(
            impl From<$typ> for $Name {
                fn from(err: $typ) -> $Name {
                    $Name::$Variant(err)
                }
            }
        )?)*

        impl std::fmt::Debug for $Name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
                match self {
                    $($Name::$Variant(err) => write!(f, "{}: {:?}", $message, err),)*
                }
            }
        }

        impl<'r> rocket::response::Responder<'r, 'static> for $Name {
            fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'static> {
                match self {
                    $($(
                        $Name::$Variant($err) => $respond_to,
                    )?)*
                    err => panic!("Unhandled {err:?}"),
                }
            }
        }
    };

    (
        $(#[$meta:meta])*
        $vis:vis enum $Name:ident {
            $($message:literal $Variant:ident($typ:ty),)*
        }
    ) => {
        error_enum!(
            $(#[$meta])*
            $vis enum $Name {
                $($Variant($typ) => $message,)*
            }
        );
    };

    (
        $(#[$meta:meta])*
        $vis:vis enum $Name:ident {
            $($Variant:ident($typ:ty),)*
        }
    ) => {
        error_enum!(
            $(#[$meta])*
            $vis enum $Name {
                $($Variant($typ) => stringify!($Variant),)*
            }
        );
    };
}

#[macro_export]
macro_rules! redis_error_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $Name:ident {
            Redis($RedisError:ty) => $redis_message:expr,
            $($Variant:ident$(($typ:ty))? => $message:expr $(
                => $err:ident => $respond_to:expr
            )?,)*
        }
    ) => {
        error_enum!(
            $(#[$meta])*
            $vis enum $Name {
                Redis($RedisError) => $redis_message => err => {
                    match err {
                        // If the redis connection dropped or it was an IO error, tell the client to try again
                        // in 30 seconds (hopefully redis is back up!)
                        err if err.is_io_error() || err.is_connection_dropped() => {
                            eprintln!("Warning: redis connection dropped");
                            let message = "service temporarily unavailable";
                            Ok(rocket::Response::build()
                                .status(http::Status::ServiceUnavailable)
                                .raw_header("Retry-After", "30")
                                .sized_body(message.len(), std::io::Cursor::new(message))
                                .finalize())
                        }
                        // If redis is loading data, tell the client to retry in 20 seconds
                        err if err.kind() == redis::ErrorKind::BusyLoadingError => {
                            eprintln!("Warning: redis server busy loading");
                            let message = "service temporarily unavailable";
                            Ok(rocket::Response::build()
                                .status(http::Status::ServiceUnavailable)
                                .raw_header("Retry-After", "20")
                                .sized_body(message.len(), std::io::Cursor::new(message))
                                .finalize())
                        }
                        // If redis asked to try again, get the client to try again in 5 seconds
                        err if err.kind() == redis::ErrorKind::TryAgain => {
                            eprintln!("Warning: redis server busy loading");
                            let message = "please try again";
                            Ok(rocket::Response::build()
                                .status(http::Status::ServiceUnavailable)
                                .raw_header("Retry-After", "5")
                                .sized_body(message.len(), std::io::Cursor::new(message))
                                .finalize())
                        }
                        err => panic!("Redis error: {err:?}"),
                    }
                },
                $($Variant$(($typ))? => $message $(=> $err => $respond_to)?,)*
            }
        );
    };

    (
        $(#[$meta:meta])*
        $vis:vis enum $Name:ident {
            $redis_message:literal Redis($RedisError:ty),
            $($message:literal $Variant:ident($typ:ty),)*
        }
    ) => {
        redis_error_enum!(
            $(#[$meta])*
            $vis enum $Name {
                Redis($RedisError:ty) => $redis_message,
                $($Variant($typ) => $message,)*
            }
        );
    };

    (
        $(#[$meta:meta])*
        $vis:vis enum $Name:ident {
            Redis($RedisError:ty),
            $($Variant:ident($typ:ty),)*
        }
    ) => {
        redis_error_enum!(
            $(#[$meta])*
            $vis enum $Name {
                Redis($RedisError) => "Redis",
                $($Variant($typ) => stringify!($Variant),)*
            }
        );
    };
}
