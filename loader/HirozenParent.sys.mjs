/* Hirozen actor parent: the parent-process half of the loader-owned "Hirozen" JSWindowActor.
 *
 * It is deliberately empty. The loader calls `getActor("Hirozen").sendQuery(name, data)` on the
 * browsing context's own WindowGlobalParent (loader.sys.mjs #query) and the child answers straight
 * back, so there is nothing to route here. The class still has to exist under this exact name:
 * JSActor looks up `<ActorName>Parent` in the parent module, the same way it looks up
 * `<ActorName>Child` in the child module (S1 F4).
 */
export class HirozenParent extends JSWindowActorParent {}
