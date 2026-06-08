import {Eta} from 'eta';

export class ThemeRender {
    private themePath: string;
    private eta: Eta;
    private requestRoot: string;
    constructor(themePath: string, requestRoot: string = '/') {
        this.requestRoot = requestRoot;
        this.themePath = themePath;
        this.eta = new Eta({
            views: this.themePath,
            cache: true
        });
    }

    render(templatePath: string, data: any): string {
        return this.eta.render(templatePath, {...data, request_root: this.requestRoot});
    }
}