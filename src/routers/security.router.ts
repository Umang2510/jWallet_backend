import { Router } from 'express';

import HttpStatusCodes from '#src/common/constants/HttpStatusCodes.ts';
import Paths from '#src/common/constants/Paths/index.ts';
import { requestContext } from '#src/common/utils/request.utils.ts';
import { sendSuccess } from '#src/common/utils/response.utils.ts';
import Security, {
  type ChangePinInput,
  type SetPinInput,
} from '#src/entities/Security/index.ts';
import { getAuth, requireAuth, requireScope } from '#src/middleware/auth.ts';
import { validateBody } from '#src/middleware/validate.ts';
import PinService from '#src/services/PinService.ts';

// ========================================================================= //
//                                   EXEC                                    //
// ========================================================================= //

const router = Router();

router.use(requireAuth, requireScope('security:manage'));

// Set the first transaction PIN (mandatory after first login).
router.post(
  Paths.Security.SetPin.PATH,
  validateBody(Security.Schemas.SetPin),
  async (req, res) => {
    const { pin } = req.body as SetPinInput;
    const result = await PinService.setPin(
      getAuth(res),
      pin,
      requestContext(req, res),
    );
    sendSuccess(res, HttpStatusCodes.CREATED, 'Transaction PIN set', result);
  },
);

// Change the PIN (current PIN required).
router.put(
  Paths.Security.ChangePin.PATH,
  validateBody(Security.Schemas.ChangePin),
  async (req, res) => {
    const { currentPin, newPin } = req.body as ChangePinInput;
    const result = await PinService.changePin(
      getAuth(res),
      currentPin,
      newPin,
      requestContext(req, res),
    );
    sendSuccess(res, HttpStatusCodes.OK, 'Transaction PIN changed', result);
  },
);

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default router;
