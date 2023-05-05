# Project files structure

.
├── composer.json
├── package.json
│
└── src/
    ├── class-initializer.php        ← primary backend file
    └── client/
        └── block-editor/
            └── blocks/
                └── n-block/
                    ├── block.json               ← block metadata
                    ├── index.js                 ← block registration plugin
                    ├── editor.scss              ← styles loaded only in the editor
                    ├── style.scss               ← styles loaded in both contexts (editro and frontend)
                    ├── view.js                  ← script loaded on the frontend
                    └── view.scss                ← styles loaded on the frontend
 