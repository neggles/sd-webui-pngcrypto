# sd-webui-pngcrypto

This extension embeds image generation metadata into the (unused) alpha channel of a PNG generated in [stable-diffusion-webui](https://github.com/AUTOMATIC1111/stable-diffusion-webui), and as a bonus,
encrypts its metadata with AES-256-EAX encryption.

**Will not work for JPEG images.** Untested on webp, should work in theory but who knows.

---

*Please note that as this data is embedded in the image pixels, it is not visible in an EXIF data viewer.*  
***This will not strip the text metadata from the image, nor will it encrypt it. You will have to clean the text metadata yourself.***

---

It will show up in the PNG info tab in the webui. Extension auto-activates and runs alongside standard webui PNG info functions, no extra settings are required. It can optionally be disabled in settings if desired.

### Acknowledgements

Based on my fork of @ashen-sensored's [sd_webui_stealth_pnginfo](https://github.com/ashen-sensored/sd_webui_stealth_pnginfo)
which you can find [here](https://github.com/neggles/sd-webui-stealth-pnginfo). 

<br/>

<sub>I'm sorry, ashen ._.</sub>
