# Fotos Puente

App web para pasar fotos y videos del iPhone a la compu, ordenados por carpeta.
Publicada en Netlify: https://fotos-puente-diego.netlify.app

- `public/` — la app (HTML, manifest e íconos)
- `netlify/functions/api.mts` — servidor: login, subida por partes, galería (Netlify Blobs)

Las credenciales viven en variables de Netlify (`APP_USER`, `APP_PASS`, `APP_SECRET`), no en el código.
