%% Copyright (c) 2012 eZuce, Inc. All rights reserved.
%% Contributed to SIPfoundry under a Contributor Agreement
%%
%% This software is free software; you can redistribute it and/or modify it under
%% the terms of the Affero General Public License (AGPL) as published by the
%% Free Software Foundation; either version 3 of the License, or (at your option)
%% any later version.
%%
%% This software is distributed in the hope that it will be useful, but WITHOUT
%% ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
%% FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
%% details.

-module(cpx_agent_web_listener).
-author("jvliwanag").

-behaviour(gen_server).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-include("oacd_web.hrl").

%% api
-export([start/0, start/1, start_link/0, start_link/1, stop/0]).

-record(state, {http_pid:: pid()}).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(DISPATCH,
[{'_', [
	{[], cowboy_http_static,
		[{directory, {priv_dir, oacd_web, [<<"www">>, <<"agent">>]}},
		{mimetypes, {fun mimetypes:path_to_mimes/2, default}},
		{file, <<"index.html">>}]},
	{[<<"static">>, <<"agent">>, '...'], cowboy_http_static,
		[{directory, {priv_dir, oacd_web, [<<"www">>, <<"agent">>]}},
		{mimetypes, {fun mimetypes:path_to_mimes/2, default}}]},
	{[<<"static">>, <<"contrib">>, '...'], cowboy_http_static,
		[{directory, {priv_dir, oacd_web, [<<"www">>, <<"contrib">>]}},
		{mimetypes, {fun mimetypes:path_to_mimes/2, default}}]},
	{[<<"wsock">>], cpx_agent_wsock_handler,
		[]},
	{[<<"api">>], cpx_agent_web_handler,
		[]}]}]
).

%% @doc Starts the web listener on the default port of 5055.
-spec(start/0 :: () -> {'ok', pid()}).
start() ->
	start([]).

%% @doc Starts the web listener on the passed port.
-spec(start/1 :: (Port :: non_neg_integer()) -> {'ok', pid()}).
start(Port) when is_integer(Port) ->
	start([{port, Port}]);
start(Options) ->
	gen_server:start({local, ?MODULE}, ?MODULE, Options, []).

%% @doc Start linked on the default port of 5055.
-spec(start_link/0 :: () -> {'ok', pid()}).
start_link() ->
	start_link([]).

%% @doc Start linked on the given port.
-spec(start_link/1 :: (Port :: non_neg_integer()) -> {'ok', pid()}).
start_link(Port) when is_integer(Port) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Port], []);
start_link(Options) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Options, []).

%% @doc Stop the web listener.
-spec(stop/0 :: () -> 'ok').
stop() ->
	gen_server:call(?MODULE, stop).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init(Options) ->
	process_flag(trap_exit,true),
	Port = proplists:get_value(port, Options, ?DEFAULT_PORT),

	{ok, Pid} = cowboy:start_listener(oacd_web_http, 100,
		cowboy_tcp_transport, [{port, Port}],
		cowboy_http_protocol, [{dispatch, ?DISPATCH}]),

	{ok, #state{http_pid = Pid}}.

handle_call(stop, _From, State) ->
	{stop, normal, ok, State};
handle_call(Request, _From, State) ->
    {reply, {unknown_call, Request}, State}.

handle_cast(_Msg, State) ->
	{noreply, State}.

handle_info(_Info, State) ->
	{noreply, State}.

terminate(Reason, #state{}) ->
	lager:notice("stopping web listener: ~p", [Reason]),
	cowboy:stop_listener(oacd_web_http),
	ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

-ifdef(TEST).

start_test_() ->
	CBPid = spawn(fun() -> ok end),

	{setup,
	fun() ->
		meck:new(cowboy),
		meck:expect(cowboy, start_listener,
			fun(_, _, _, _, _, _) -> {ok, CBPid} end),
		meck:expect(cowboy, stop_listener, 1, ok)
	end,
	fun(_) ->
		meck:unload(cowboy)
	end,
	{foreach, fun() -> ok end, fun(_) -> catch cpx_agent_web_listener:stop() end,
	[{"start/stop", fun() ->
		{ok, Pid} = cpx_agent_web_listener:start(),
		cpx_agent_web_listener:stop(),

		?assert(not is_name_alive(cpx_agent_web_listener)),
		?assert(meck:called(cowboy, stop_listener, [oacd_web_http], Pid))
	end},
	{"abnormal stop", fun() ->
		{ok, Pid} = cpx_agent_web_listener:start(),
		?assertEqual({trap_exit, true} , erlang:process_info(Pid, trap_exit)),
		terminate(shutdown, #state{}),
		?assert(meck:called(cowboy, stop_listener, [oacd_web_http], self()))
	end},
	{"start with no opts", fun() ->
		{ok, Pid} = cpx_agent_web_listener:start(),

		?assert(meck:called(cowboy, start_listener,
			[oacd_web_http, 100,
			cowboy_tcp_transport, [{port, ?DEFAULT_PORT}],
			cowboy_http_protocol, [{dispatch, ?DISPATCH}]], Pid))
	end},
	{"start with port", fun() ->
		{ok, Pid} = cpx_agent_web_listener:start(9123),
		?assert(meck:called(cowboy, start_listener,
			[oacd_web_http, 100,
			cowboy_tcp_transport, [{port, 9123}],
			cowboy_http_protocol, [{dispatch, ?DISPATCH}]], Pid))
	end}
	]}}.

is_name_alive(Name) ->
	Pid = erlang:whereis(Name),
	Pid =/= undefined andalso erlang:is_process_alive(Pid).

-endif.
