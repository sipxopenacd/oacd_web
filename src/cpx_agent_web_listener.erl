%%	The contents of this file are subject to the Common Public Attribution
%%	License Version 1.0 (the “License”); you may not use this file except
%%	in compliance with the License. You may obtain a copy of the License at
%%	http://opensource.org/licenses/cpal_1.0. The License is based on the
%%	Mozilla Public License Version 1.1 but Sections 14 and 15 have been
%%	added to cover use of software over a computer network and provide for
%%	limited attribution for the Original Developer. In addition, Exhibit A
%%	has been modified to be consistent with Exhibit B.
%%
%%	Software distributed under the License is distributed on an “AS IS”
%%	basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
%%	License for the specific language governing rights and limitations
%%	under the License.
%%
%%	The Original Code is OpenACD.
%%
%%	The Initial Developers of the Original Code is
%%	Andrew Thompson and Micah Warren.
%%
%%	All portions of the code written by the Initial Developers are Copyright
%%	(c) 2008-2009 SpiceCSM.
%%	All Rights Reserved.
%%
%%	Contributor(s):
%%
%%	Jan Vincent Liwanag / eZuce <jvliwanag at ezuce dot com>
%%

-module(cpx_agent_web_listener).
-author("jvliwanag").

-behaviour(gen_server).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-include("oacd_web.hrl").
-include_lib("oacd_core/include/log.hrl").

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
	?NOTICE("stopping web listener: ~p", [Reason]),
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