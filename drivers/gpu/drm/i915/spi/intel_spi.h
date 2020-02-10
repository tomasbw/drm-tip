/* SPDX-License-Identifier: MIT */
/*
 * Copyright(c) 2019-2021, Intel Corporation. All rights reserved.
 */

#ifndef __INTEL_SPI_H__
#define __INTEL_SPI_H__

struct drm_i915_private;

#define I915_SPI_REGIONS 13
struct i915_spi_region {
	const char *name;
};

struct intel_spi {
	struct drm_i915_private *i915;
};

void intel_spi_init(struct intel_spi *spi, struct drm_i915_private *i915);

#endif /* __INTEL_SPI_H__ */
