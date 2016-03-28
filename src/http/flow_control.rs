//! The module exposes the `WindowUpdateStrategy` trait, a trait used for defining how a flow
//! control window should be updated.
//!
//! A basic implementation of this trait which effectively disables flow control is also provided.

use http::{StreamId, WindowSize, DEFAULT_MAX_WINDOW_SIZE};

/// Defines the possible actions that can be taken to update flow control.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum WindowUpdateAction {
    /// Take no action -- do not change flow control
    NoAction,
    /// Increase the flow control window by the given amount
    Increment(u32),
}

/// A trait that should be implemented by types that are able to serve as algorithms for flow
/// control.
pub trait WindowUpdateStrategy {
    /// Return the action that should be taken with respect to the connection-level flow control
    /// window.
    fn on_connection_window(&mut self,
                            new: WindowSize)
                            -> WindowUpdateAction;

    /// Return the action that should be taken with respect to a stream-level flow control window.
    fn on_stream_window(&mut self,
                        stream_id: StreamId,
                        new: WindowSize)
                        -> WindowUpdateAction;
}

/// Provides an implementation of the `WindowUpdateStrategy` trait which effectively disables flow
/// control by updating the window sizes immediately after each decrease.
pub struct NoFlowControlStrategy {
    max_connection_window_size: WindowSize,
    max_stream_window_size: WindowSize,
}

impl NoFlowControlStrategy {
    /// Creates a new `NoFlowControlStrategy` which uses the default maximum window size for both
    /// the connection, as well as the stream windows.
    pub fn new() -> NoFlowControlStrategy {
        NoFlowControlStrategy::with_max_window_sizes(DEFAULT_MAX_WINDOW_SIZE,
                                                     DEFAULT_MAX_WINDOW_SIZE)
    }

    /// Creates a new `NoFlowControlStrategy` with the given maximum size of the connection and
    /// stream windows.
    pub fn with_max_window_sizes(max_connection: WindowSize,
                                 max_stream: WindowSize)
                                 -> NoFlowControlStrategy {
        NoFlowControlStrategy {
            max_connection_window_size: max_connection,
            max_stream_window_size: max_stream,
        }
    }

    /// A private helper function that decides the action depending on the current window size and
    /// the maximum window size. The action is always such that the current size gets increased to
    /// the maximum size.
    fn compute_update(current: WindowSize, max: WindowSize) -> WindowUpdateAction {
        let current: i32 = current.into();
        let max: i32 = max.into();
        let delta = max - current;
        if delta <= 0 {
            WindowUpdateAction::NoAction
        } else {
            WindowUpdateAction::Increment(delta as u32)
        }
    }
}

impl WindowUpdateStrategy for NoFlowControlStrategy {
    #[inline]
    fn on_connection_window(&mut self,
                            new: WindowSize)
                            -> WindowUpdateAction {
        NoFlowControlStrategy::compute_update(new, self.max_connection_window_size)
    }

    #[inline]
    fn on_stream_window(&mut self,
                        _stream_id: StreamId,
                        new: WindowSize)
                        -> WindowUpdateAction {
        NoFlowControlStrategy::compute_update(new, self.max_stream_window_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::WindowSize;

    #[test]
    fn test_window_update_no_flow_ctrl() {
        {
            let mut strat = NoFlowControlStrategy::new();
            let action = strat.on_connection_window(WindowSize(0));
            assert_eq!(action, WindowUpdateAction::Increment(0xffff));
        }
        {
            let mut strat = NoFlowControlStrategy::new();
            let action = strat.on_connection_window(WindowSize(1));
            assert_eq!(action, WindowUpdateAction::Increment(0xffff - 1));
        }
        {
            let mut strat = NoFlowControlStrategy::new();
            let action = strat.on_connection_window(WindowSize(0xffff + 1));
            assert_eq!(action, WindowUpdateAction::NoAction);
        }
        {
            let mut strat = NoFlowControlStrategy::new();
            let action = strat.on_stream_window(1, WindowSize(0));
            assert_eq!(action, WindowUpdateAction::Increment(0xffff));
        }
        {
            let mut strat = NoFlowControlStrategy::new();
            let action = strat.on_stream_window(1, WindowSize(1));
            assert_eq!(action, WindowUpdateAction::Increment(0xffff - 1));
        }
        {
            let mut strat = NoFlowControlStrategy::new();
            let action = strat.on_stream_window(1, WindowSize(0xffff + 1));
            assert_eq!(action, WindowUpdateAction::NoAction);
        }
    }
}
