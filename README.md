# Chaoyu Zhang's academic website

This repository contains the source for [chaoyuvt.github.io](https://chaoyuvt.github.io/), hosted with GitHub Pages and built with the [Academic Pages](https://github.com/academicpages/academicpages.github.io) Jekyll theme.

## Site content

- `_pages/about.md` — homepage, research interests, and news
- `_pages/publications.html` and `_publications/` — publication list
- `_pages/teaching.html` and `_teaching/` — teaching experience
- `_pages/cv.md` — curriculum vitae
- `_pages/contact.md` — contact information
- `_config.yml` — site metadata, navigation, and author profile
- `images/` — profile, favicon, and site images

The homepage is defined only by `_pages/about.md`, which owns the `/` permalink.

## Local preview

```bash
bundle install
bundle exec jekyll serve
```

Changes pushed to `main` are deployed automatically by GitHub Pages.

The theme remains subject to its original license in `LICENSE`.
