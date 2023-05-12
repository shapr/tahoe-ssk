-- | Expose the library's public interface.
module Tahoe.SDMF (
    module Tahoe.SDMF.Internal.Share,
    module Tahoe.SDMF.Internal.Capability,
) where

import Tahoe.SDMF.Internal.Capability (Reader (..), Writer (..))
import Tahoe.SDMF.Internal.Share (Share (..))
