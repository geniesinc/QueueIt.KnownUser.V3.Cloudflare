import { validateToken } from './validateToken';

const jwt = require('jsonwebtoken');

const DC_EDITION_QUEUES = 'editionqueues';

export const checkWaitingRoom = async (request: any, queueitToken: string, idToken: string): Promise<boolean> => {

  const requestUrl = request.url;

  // check statsig config only for reserveNFT
  if (idToken && !queueitToken && requestUrl.includes("reserveNFT")) {
      const statsig = require('statsig-node');
      try {
          await statsig.initialize(
            STATSIG_SECRET_KEY,
            { environment: { tier: STATSIG_ENVIRONMENT_TIER  }}
          );
      } catch (e) {
          console.log("caught error statsig init: ", e);
      }

      let decodedIdToken = jwt.decode(idToken, {complete: true});
      if (!decodedIdToken) {
          console.log("decodedIdToken is null");
          return false
      }

      // check if id token is expired
      if (decodedIdToken.payload['exp'] &&
          decodedIdToken.payload['exp'] * 1000 < Date.now()) {
          console.log("expired token");
          return false;
      }

      const isValid = await validateToken(idToken);
      console.log("isValid: ", isValid);
      if (!isValid) {
          console.log("idToken is not valid");
          return false;
      }

      let editionQueues: any;
      try {
          editionQueues = await statsig.getConfig({ 
              userID: decodedIdToken.payload['sub'],
              email: decodedIdToken.payload['email'],
              custom: {
                  phoneNumber: decodedIdToken.payload['phone_number'],
              }
          },
          DC_EDITION_QUEUES);
          await statsig.shutdown();
      } catch (e) {
          console.log("caught error getting config: ", e);
      }
      
      const body = await request.clone().json();
      const editionFlowId = body.variables.input.editionFlowID ?? -1;
      const isEditionIncluded = editionQueues.value.editionFlowIds.includes(editionFlowId);

      // skip queue-it validation if edition flow id is not in dynamic config
      if (!isEditionIncluded) {
          return true;
      }
    }
    return false;
}
