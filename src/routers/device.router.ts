import { Router } from 'express';

import HttpStatusCodes from '#src/common/constants/HttpStatusCodes.ts';
import Paths from '#src/common/constants/Paths/index.ts';
import { requestContext } from '#src/common/utils/request.utils.ts';
import { sendSuccess } from '#src/common/utils/response.utils.ts';
import Security, {
  type EnrollBiometricInput,
} from '#src/entities/Security/index.ts';
import { getAuth, requireAuth, requireScope } from '#src/middleware/auth.ts';
import { validateBody } from '#src/middleware/validate.ts';
import DeviceService from '#src/services/DeviceService.ts';

// ========================================================================= //
//                                   EXEC                                    //
// ========================================================================= //

const router = Router();

router.use(requireAuth, requireScope('security:manage'));

// Enroll this device's biometric key (PIN required).
router.post(
  Paths.Devices.Biometric.PATH,
  validateBody(Security.Schemas.EnrollBiometric),
  async (req, res) => {
    const { publicKey, pin } = req.body as EnrollBiometricInput;
    const result = await DeviceService.enrollBiometric(
      getAuth(res),
      publicKey,
      pin,
      requestContext(req, res),
    );
    sendSuccess(res, HttpStatusCodes.OK, 'Biometric approval enabled', result);
  },
);

// Turn biometric approval off on this device.
router.delete(Paths.Devices.Biometric.PATH, async (req, res) => {
  const result = await DeviceService.removeBiometric(
    getAuth(res),
    requestContext(req, res),
  );
  sendSuccess(res, HttpStatusCodes.OK, 'Biometric approval disabled', result);
});

// ========================================================================= //
//                                  EXPORT                                   //
// ========================================================================= //

export default router;
