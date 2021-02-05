%% Run on Matlab2012b 
clc;clear;close all;
alpha = 80;
im = double(imread('original.jpg'))/255;
snow = double(imread('snow.jpg'))/255;
imsize = size(im);

FB = fft2(snow);
FA = fft2(im);
mark_ = (FB-FA)/alpha;

TH=mark_(1:imsize(1)*0.5,1:imsize(2),:);
load('encode.mat','M','N');
TH1=zeros(imsize(1)*0.5,imsize(2),imsize(3));
for i=1:imsize(1)*0.5
    for j=1:imsize(2)
         TH1(M(i),N(j),:)=TH(i,j,:);
    end
end
imwrite(TH1,'watermark.png');