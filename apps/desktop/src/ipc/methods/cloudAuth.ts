import {
  DesktopCloudAuthGetTokenInputSchema,
  DesktopCloudAuthStateSchema,
} from "@t3tools/contracts";
import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";

import * as DesktopCloudAuth from "../../app/DesktopCloudAuth.ts";
import * as IpcChannels from "../channels.ts";
import { makeIpcMethod } from "../DesktopIpc.ts";

export const getCloudAuthState = makeIpcMethod({
  channel: IpcChannels.CLOUD_AUTH_GET_STATE_CHANNEL,
  payload: Schema.Void,
  result: DesktopCloudAuthStateSchema,
  handler: Effect.fn("desktop.ipc.cloudAuth.getState")(function* () {
    return yield* (yield* DesktopCloudAuth.DesktopCloudAuth).getState;
  }),
});

export const getCloudAuthAccessToken = makeIpcMethod({
  channel: IpcChannels.CLOUD_AUTH_GET_ACCESS_TOKEN_CHANNEL,
  payload: Schema.UndefinedOr(DesktopCloudAuthGetTokenInputSchema),
  result: Schema.NullOr(Schema.String),
  handler: Effect.fn("desktop.ipc.cloudAuth.getAccessToken")(function* (input) {
    return yield* (yield* DesktopCloudAuth.DesktopCloudAuth).getAccessToken(input);
  }),
});

export const signInCloudAuth = makeIpcMethod({
  channel: IpcChannels.CLOUD_AUTH_SIGN_IN_CHANNEL,
  payload: Schema.Void,
  result: DesktopCloudAuthStateSchema,
  handler: Effect.fn("desktop.ipc.cloudAuth.signIn")(function* () {
    return yield* (yield* DesktopCloudAuth.DesktopCloudAuth).signIn;
  }),
});

export const signOutCloudAuth = makeIpcMethod({
  channel: IpcChannels.CLOUD_AUTH_SIGN_OUT_CHANNEL,
  payload: Schema.Void,
  result: DesktopCloudAuthStateSchema,
  handler: Effect.fn("desktop.ipc.cloudAuth.signOut")(function* () {
    return yield* (yield* DesktopCloudAuth.DesktopCloudAuth).signOut;
  }),
});
